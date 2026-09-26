#!/usr/bin/env bash
# Builder-only compilation; all fault writes use a private, bounded tmpfs.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  printf 'Run as root to create an isolated mount namespace\n' >&2
  exit 2
fi
exec unshare --mount --propagation private bash -c '
set -euo pipefail
fault_root="$(mktemp -d)"
trap '\''umount "$fault_root"; rmdir "$fault_root"'\'' EXIT
mount -t tmpfs -o size=1m,nr_inodes=64 tmpfs "$fault_root"
export AENV_TEST_ENOSPC_DIR="$fault_root"
cargo test --locked -p overlaybd --lib test_snapshot_copy_real_enospc_keeps_live_disk_writable -- --ignored --nocapture
'
