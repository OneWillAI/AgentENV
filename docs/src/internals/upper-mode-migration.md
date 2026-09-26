# Memory-preserving upper-mode migration

`ublk.overlaybd.runtime_upper_mode` selects the format for newly created writable
uppers. It does not reinterpret an existing upper. Retained cold boots now use
that policy too, but a tools upgrade/cold boot loses the old RAM session and is
not a storage-mode migration.

For memory-preserving migration, explicitly enable:

```toml
[ublk.overlaybd]
restore_log_upper_as_hybrid = true
```

The default is false. This node policy applies when constructing a **memory
restore**, including pause/resume and launches from memory snapshots. It changes
only the new rootfs upper's format when the saved runtime mode is `logStructured`.
Sparse/hybrid/read-only rootfs configurations and startup-pack recording are
unchanged. The source must be an immutable exported checkpoint with no writable
upper, and its rootfs and ublk configurations must agree. Otherwise migration
fails before allocating a storage device. The checkpoint files are never edited.

For an existing computer:

1. Provide enough free capacity for the full memory/disk preservation output,
   current writable files, and retained rollback generations. Use normal
   preservation preflight; do not delete recovery evidence to bypass it.
2. Use the normal authenticated pause operation (`POST /sandboxes/{sandboxID}/pause`)
   and require successful capture, durable publication and runtime/storage stop.
   A failure is not permission to discard or replace the old writable files.
3. Resume the same ID (`POST /sandboxes/{sandboxID}/resume`) on a worker with this
   policy enabled. It restores the same CPU/device/RAM checkpoint and tools
   release, but materializes a fresh hybrid rootfs upper over the saved lowers.
4. Verify the running upper's physical format, the unchanged computer/tools/SSH
   identity, process continuity and guest data. Subsequent memory captures record
   the hybrid runtime mode. Keep the previous checkpoint until normal
   reference-aware retention permits collecting it.

Enabling this policy does not migrate already running devices. Snapshot-and-
continue exports a compact copy while leaving the running upper intact. Do not
use a periodic snapshot job, a tools-upgrade endpoint, live `image.json` edits,
file truncation, or file replacement as substitutes for preserve/stop/restore.
A worker restart needed to apply configuration must itself use the preservation
protocol. Product environment deployment requires its own authorization.

Attached drives use their configured creation policy; existing source uppers
retain their physical format. This opt-in policy changes only the restored
rootfs. It does not silently rewrite attached-drive or persistent-volume data.

Hybrid writes reuse data extents for overwrites and discard/rewrite. Index
mapping records can still grow with discard transitions; new unique blocks and
retained checkpoint/rollback files consume additional storage. Data-extent reuse
is not a hard bound on total disk usage. Any online index compaction needs a
separate crash-safe design; this change introduces no live file rotation.

Policy unit tests verify selection, refusal, and unchanged checkpoint bytes and
metadata. Real VM acceptance must additionally prove a RAM-only nonce and
process PID/start-time survive, checksummed files and dirty Git changes remain,
SQLite integrity and records survive, and previously trusted authenticated SSH,
published ports, and tools versions remain usable. Unit tests alone do not
certify those properties.
