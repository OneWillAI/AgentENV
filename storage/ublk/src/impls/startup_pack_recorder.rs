//! First-touch page recorder for the startup memory pack.
//!
//! Attached to an `OverlaybdTarget` while a throwaway VM re-resumes a freshly
//! captured snapshot. Every read submitted to the device marks its 4 KiB
//! pages in an atomic bitmap; the thread that actually flips a bit appends
//! the page to the ordered first-touch log (exactly-once; the only lock is a
//! short log append on reads that mark new pages — the activity clocks are
//! lock-free). Completion latency feeds a heuristic remote-bytes estimate
//! reported in the recording log: local pread/cache hits are ~0.1 ms while
//! an OSS refill is ~20 ms, so a slow read that touched new pages is treated
//! as remote-served — a useful quality signal without plumbing cache
//! attribution through the whole layer stack.

use anyhow::{bail, ensure, Context, Result};
use overlaybd::startup_pack::PACK_PAGE_BYTES;
use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bitmap coverage cap: 16 GiB of device space (512 KiB of bitmap words).
/// Pages above it are counted but never recorded.
const BITMAP_MAX_PAGES: u64 = 4 * 1024 * 1024;

/// A read slower than this was almost certainly served by a remote fetch
/// (local pread and cache hits are ~0.1 ms; OSS refills are ~20 ms).
const REMOTE_LATENCY_THRESHOLD: Duration = Duration::from_millis(10);

pub struct StartupPackRecorder {
    mem_virtual_size: u64,
    bitmap: Vec<AtomicU64>,
    log: Mutex<Vec<u32>>,
    max_pages: usize,
    /// Pages ever marked in the bitmap (log may be capped below this).
    total_marked: AtomicU64,
    /// Pages above the bitmap coverage cap.
    skipped_high_pages: AtomicU64,
    in_flight: AtomicI64,
    remote_bytes: AtomicU64,
    armed_at: Instant,
    first_read_at: std::sync::OnceLock<Instant>,
    /// Nanoseconds since `armed_at` of the last observed activity; fetch_max
    /// keeps it monotonic without a lock on the read path.
    last_activity_nanos: AtomicU64,
}

impl std::fmt::Debug for StartupPackRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupPackRecorder")
            .field("mem_virtual_size", &self.mem_virtual_size)
            .field("log_pages", &self.log.lock().len())
            .field("total_marked", &self.total_marked.load(Ordering::Relaxed))
            .field(
                "skipped_high_pages",
                &self.skipped_high_pages.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

/// Decision returned by [`StartupPackRecorder::verdict`] on each daemon tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingVerdict {
    Continue,
    /// Window finished; finalize the pack.
    Finish,
    /// Abort the pack (low-quality recording).
    Fail(&'static str),
}

/// Outcome of a successful finalize pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizeOutcome {
    pub pages: u32,
    /// Memory bytes covered by the trace (pages × 4 KiB).
    pub bytes: u64,
    pub remote_bytes: u64,
    /// Pages above the 16 GiB bitmap coverage cap (never recorded).
    pub skipped_high_pages: u64,
}

impl StartupPackRecorder {
    pub fn new(mem_virtual_size: u64, max_pages: usize) -> Self {
        let bitmap_pages = (mem_virtual_size / PACK_PAGE_BYTES).min(BITMAP_MAX_PAGES);
        let words = usize::try_from(bitmap_pages.div_ceil(64)).unwrap_or(usize::MAX);
        let mut bitmap = Vec::with_capacity(words);
        bitmap.resize_with(words, || AtomicU64::new(0));
        Self {
            mem_virtual_size,
            bitmap,
            log: Mutex::new(Vec::new()),
            max_pages,
            total_marked: AtomicU64::new(0),
            skipped_high_pages: AtomicU64::new(0),
            in_flight: AtomicI64::new(0),
            remote_bytes: AtomicU64::new(0),
            armed_at: Instant::now(),
            first_read_at: std::sync::OnceLock::new(),
            last_activity_nanos: AtomicU64::new(0),
        }
    }

    /// Stamp the activity clock (nanoseconds since arm) without a lock.
    fn touch_activity(&self) {
        let nanos = self.armed_at.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.last_activity_nanos.fetch_max(nanos, Ordering::Relaxed);
    }

    /// Nanoseconds since the last observed activity (0 when never active).
    fn idle_nanos(&self) -> u64 {
        let now = self.armed_at.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        now.saturating_sub(self.last_activity_nanos.load(Ordering::Relaxed))
    }

    /// Record the pages covered by a read at submission time (the order the
    /// daemon sees requests ≈ the guest's fault order). Returns true when the
    /// read marked at least one previously-unseen page, so the completion
    /// path can attribute remote latency to new pages only.
    pub fn observe_submit(&self, offset: u64, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let _ = self.first_read_at.set(Instant::now());
        let first_page = offset / PACK_PAGE_BYTES;
        let end_page = (offset + len as u64).div_ceil(PACK_PAGE_BYTES);
        let bitmap_pages = self.bitmap.len() as u64 * 64;
        let mut new_pages: Vec<u32> = Vec::new();
        for page in first_page..end_page {
            if page >= bitmap_pages {
                self.skipped_high_pages.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let word = &self.bitmap[(page / 64) as usize];
            let mask = 1u64 << (page % 64);
            if word.fetch_or(mask, Ordering::Relaxed) & mask == 0 {
                new_pages.push(page as u32);
            }
        }
        if new_pages.is_empty() {
            return false;
        }
        self.total_marked
            .fetch_add(new_pages.len() as u64, Ordering::Relaxed);
        {
            let mut log = self.log.lock();
            let remaining = self.max_pages.saturating_sub(log.len());
            let take = remaining.min(new_pages.len());
            log.extend_from_slice(&new_pages[..take]);
        }
        self.touch_activity();
        true
    }

    /// Start tracking one in-flight read. The returned guard settles the
    /// completion (in-flight count, latency-based remote estimate) on drop.
    /// `touched_new` comes from [`Self::observe_submit`]: a slow completion
    /// only feeds the remote-bytes estimate when the read marked new pages,
    /// so re-reads of already-recorded pages never trip the abort guard.
    pub fn read_guard(self: &Arc<Self>, bytes: u64, touched_new: bool) -> StartupPackReadGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        StartupPackReadGuard {
            recorder: Arc::clone(self),
            started: Instant::now(),
            bytes,
            touched_new,
        }
    }

    fn observe_completion(&self, latency: Duration, bytes: u64, touched_new: bool) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        if touched_new && latency >= REMOTE_LATENCY_THRESHOLD {
            self.remote_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        self.touch_activity();
    }

    /// Window state machine, polled by the daemon tick.
    pub fn verdict(
        &self,
        min_window: Duration,
        quiet: Duration,
        max_window: Duration,
    ) -> RecordingVerdict {
        match self.first_read_at.get() {
            Some(first_at) => {
                let elapsed = first_at.elapsed();
                if elapsed < min_window {
                    return RecordingVerdict::Continue;
                }
                if elapsed >= max_window {
                    return RecordingVerdict::Finish;
                }
                let quiet_nanos = quiet.as_nanos().min(u64::MAX as u128) as u64;
                if self.in_flight.load(Ordering::Relaxed) == 0 && self.idle_nanos() >= quiet_nanos {
                    return RecordingVerdict::Finish;
                }
                RecordingVerdict::Continue
            }
            // No read yet: bound the no-show case by the same hard cap.
            None if self.armed_at.elapsed() >= max_window => RecordingVerdict::Finish,
            None => RecordingVerdict::Continue,
        }
    }

    pub fn remote_bytes(&self) -> u64 {
        self.remote_bytes.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn page_count(&self) -> usize {
        self.log.lock().len()
    }

    #[cfg(test)]
    pub fn is_marked(&self, page: u32) -> bool {
        let word = &self.bitmap[(page / 64) as usize];
        word.load(Ordering::Relaxed) & (1u64 << (page % 64)) != 0
    }

    #[cfg(test)]
    pub fn ordered_pages(&self) -> Vec<u32> {
        self.log.lock().clone()
    }

    /// Write the recorded first-touch page list as a trace file next to the
    /// snapshot artifacts. No page data is read back: the publisher plans the
    /// pages onto the final layer objects and packages the selected physical
    /// blocks itself, so this finalize never issues any read against the
    /// image — remote or local.
    ///
    /// `cancelled` is checked right before the final rename: when set, the
    /// pass bails and the tmp file is left for the caller's cleanup, so a
    /// cancelled trace never lands at `output`.
    pub fn finalize(&self, output: &Path, cancelled: &AtomicBool) -> Result<FinalizeOutcome> {
        let pages = self.log.lock().clone();
        ensure!(!pages.is_empty(), "no pages recorded");
        let offsets: Vec<u64> = pages
            .iter()
            .map(|page| u64::from(*page) * PACK_PAGE_BYTES)
            .collect();
        let trace = overlaybd::startup_pack::encode_trace(self.mem_virtual_size, &offsets)
            .context("encode first-touch trace")?;

        let tmp_path = tmp_pack_path(output);
        std::fs::write(&tmp_path, &trace)
            .with_context(|| format!("write trace tmp file {}", tmp_path.display()))?;
        // The rename publishes the trace; never let a cancelled recording
        // reach it (the abort path owns tmp/output cleanup afterwards).
        if cancelled.load(Ordering::Relaxed) {
            bail!("startup trace finalize cancelled before rename");
        }
        std::fs::rename(&tmp_path, output).with_context(|| {
            format!(
                "move trace into place {} -> {}",
                tmp_path.display(),
                output.display()
            )
        })?;
        Ok(FinalizeOutcome {
            pages: pages.len() as u32,
            bytes: pages.len() as u64 * PACK_PAGE_BYTES,
            remote_bytes: self.remote_bytes(),
            skipped_high_pages: self.skipped_high_pages.load(Ordering::Relaxed),
        })
    }
}

/// Tmp staging path for one pack output; the daemon's abort cleanup removes
/// it when packaging fails or is cancelled.
pub fn tmp_pack_path(output: &Path) -> PathBuf {
    let mut tmp = output.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// Settles one in-flight read on drop.
pub struct StartupPackReadGuard {
    recorder: Arc<StartupPackRecorder>,
    started: Instant,
    bytes: u64,
    touched_new: bool,
}

impl Drop for StartupPackReadGuard {
    fn drop(&mut self) {
        self.recorder
            .observe_completion(self.started.elapsed(), self.bytes, self.touched_new);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_exactly_once_append_and_first_touch_order() {
        let rec = StartupPackRecorder::new(1 << 30, 1024);
        rec.observe_submit(0x4000, 0x2000); // pages 4,5
        rec.observe_submit(0x1000, 0x1000); // page 1
        rec.observe_submit(0x4000, 0x1000); // duplicate → zero appends
        assert_eq!(rec.ordered_pages(), &[4, 5, 1]);
        assert_eq!(rec.page_count(), 3);
    }

    #[test]
    fn finalize_writes_first_touch_trace() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let output = tmp.path().join("memory-startup.trace");
        let rec = StartupPackRecorder::new(1 << 30, 1024);
        rec.observe_submit(0x4000, 0x2000); // pages 4,5
        rec.observe_submit(0x1000, 0x1000); // page 1
        let outcome = rec
            .finalize(&output, &AtomicBool::new(false))
            .expect("finalize");
        assert_eq!(outcome.pages, 3);
        assert_eq!(outcome.bytes, 3 * PACK_PAGE_BYTES);
        let (mem_vsize, offsets) =
            overlaybd::startup_pack::decode_trace(&std::fs::read(&output).expect("read trace"))
                .expect("decode trace");
        assert_eq!(mem_vsize, 1 << 30);
        assert_eq!(offsets, vec![0x4000, 0x5000, 0x1000]);
    }

    #[test]
    fn finalize_cancelled_leaves_no_trace() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let output = tmp.path().join("memory-startup.trace");
        let rec = StartupPackRecorder::new(1 << 30, 1024);
        rec.observe_submit(0, 0x1000);
        assert!(rec.finalize(&output, &AtomicBool::new(true)).is_err());
        assert!(!output.exists(), "cancelled finalize must not rename");
    }

    #[test]
    fn finalize_without_pages_fails() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let output = tmp.path().join("memory-startup.trace");
        let rec = StartupPackRecorder::new(1 << 30, 1024);
        assert!(rec.finalize(&output, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn recorder_covers_unaligned_reads_page_granular() {
        let rec = StartupPackRecorder::new(1 << 30, 1024);
        rec.observe_submit(0x1800, 0x1000); // spans pages 1 and 2
        assert!(rec.is_marked(1));
        assert!(rec.is_marked(2));
        assert!(!rec.is_marked(3));
        assert_eq!(rec.ordered_pages(), &[1, 2]);
    }

    #[test]
    fn recorder_caps_log_but_keeps_marking() {
        let rec = StartupPackRecorder::new(1 << 30, 2);
        rec.observe_submit(0, 0x3000); // 3 pages, log capacity 2
        assert_eq!(rec.page_count(), 2);
        assert!(rec.is_marked(2));
        assert_eq!(rec.total_marked.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn quiet_requires_no_new_pages_and_no_in_flight() {
        let rec = Arc::new(StartupPackRecorder::new(1 << 30, 1024));
        rec.observe_submit(0, 0x1000);
        std::thread::sleep(Duration::from_millis(5));
        let guard = rec.read_guard(0x1000, true);
        assert_eq!(
            rec.verdict(
                Duration::ZERO,
                Duration::from_millis(1),
                Duration::from_secs(60),
            ),
            RecordingVerdict::Continue,
            "in-flight read must suppress quiet"
        );
        drop(guard);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            rec.verdict(
                Duration::ZERO,
                Duration::from_millis(1),
                Duration::from_secs(60),
            ),
            RecordingVerdict::Finish,
        );
    }

    #[test]
    fn window_respects_min_max_and_no_read_bounds() {
        let rec = StartupPackRecorder::new(1 << 30, 1024);
        // min window not reached
        rec.observe_submit(0, 0x1000);
        assert_eq!(
            rec.verdict(
                Duration::from_secs(60),
                Duration::ZERO,
                Duration::from_secs(120),
            ),
            RecordingVerdict::Continue
        );
        // hard cap
        assert_eq!(
            rec.verdict(Duration::ZERO, Duration::ZERO, Duration::ZERO),
            RecordingVerdict::Finish
        );
        // no reads at all + cap elapsed
        let idle = StartupPackRecorder::new(1 << 30, 1024);
        assert_eq!(
            idle.verdict(Duration::ZERO, Duration::ZERO, Duration::ZERO),
            RecordingVerdict::Finish
        );
    }

    #[test]
    fn concurrent_submit_has_no_duplicate_pages() {
        let rec = Arc::new(StartupPackRecorder::new(1 << 30, 1 << 20));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let rec = Arc::clone(&rec);
            handles.push(std::thread::spawn(move || {
                for i in 0..10_000u64 {
                    // interleave address streams across threads
                    let page = (i % 4096) * PACK_PAGE_BYTES;
                    rec.observe_submit(page, PACK_PAGE_BYTES as usize);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("join recorder thread");
        }
        let pages = rec.ordered_pages();
        let mut dedup = pages.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(pages.len(), dedup.len(), "duplicate pages in log");
        assert_eq!(dedup.len(), 4096);
    }

    /// Hot-path micro-benchmark: the per-read increment the recorder adds to
    /// `handle_read` (observe_submit + guard create/drop). Not a criterion
    /// bench — just a regression tripwire proving the increment stays in
    /// nanoseconds per read even with contention, far below any I/O cost.
    #[test]
    fn recorder_hot_path_increment_is_negligible() {
        let rec = Arc::new(StartupPackRecorder::new(1 << 34, 1 << 20));
        let iterations = 4_000u64;
        let start = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let rec = Arc::clone(&rec);
            handles.push(std::thread::spawn(move || {
                for i in 0..iterations {
                    let offset = (i % 4096) * 256 * 1024;
                    rec.observe_submit(offset, 256 * 1024);
                    let guard = rec.read_guard(256 * 1024, true);
                    drop(guard);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("join bench thread");
        }
        let elapsed = start.elapsed();
        let per_read = elapsed / (8 * iterations) as u32;
        assert!(
            per_read < Duration::from_micros(10),
            "recorder increment too expensive: {per_read:?}/read ({elapsed:?} total)"
        );
    }
}
