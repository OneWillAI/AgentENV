# Paused Sandbox Recovery

AgentENV preserves paused-sandbox artifacts when it cannot prove that their
metadata is valid or durably indexed. Startup automatically repairs a missing
or corrupt v2 RocksDB index when its adjacent manifest is valid. It does not
guess through manifest/index disagreement, malformed manifests, or markerless
artifact generations; those items are quarantined on the local worker. A
quarantined leftover does not prevent the worker from booting: startup
releases the create-idempotency key after recording the quarantine, and
continues serving new sandboxes. `purge` is only required to discard the
retained files.

Resume drops the paused index but keeps its checkpoint artifacts. A completed
or interrupted resume may have allowed newer guest writes. Startup therefore
reports that checkpoint as requiring explicit recovery, including its capture
timestamp and the possible loss interval; a host reboot is not proof that those
writes were preserved. Legacy checkpoints have an unknown timestamp.

A later pause retains the prior generation for rollback. Collection runs after
successful ordinary/idle pauses and during shutdown preparation. An exclusive
lifecycle lock excludes pause/resume/fork/delete while references are inventoried
and collected; live guests keep running and their storage references are protected.
It keeps the current generation, the two newest successful generations (normally
current and one rollback copy), all uncertain generations, and transitive layer
references. It logs physically reclaimable bytes before deleting. Shared
hardlinks count as reclaimable only when every link will be removed. Invalid
paths, missing artifacts, ambiguous metadata, or quarantines stop collection safely.
Interrupted deletion can also require operator review; incomplete artifacts are
never guessed disposable. Typed storage fields define references; arbitrary
metadata strings do not. Startup does
not delete generations merely because the prior server is absent.

The recovery utility is intentionally host-local and has no HTTP/API surface.
Run it as a host administrator on the worker that owns the persisted-sandbox
disk. The server and utility hold the same exclusive store lock to prevent a
race. Use the utility only after safe preservation and a confirmed stop, or on
an isolated recovery copy. Never force a failed-preservation server to stop just
to acquire the lock: inspect the local preservation socket and journal first.
Standalone AgentENV Linux packages install it at
`/usr/local/sbin/aenv-paused-recovery`. Use the path present on the host:

```sh
sudo /usr/local/sbin/aenv-paused-recovery \
  --store /var/lib/aenv/persisted-sandboxes list
sudo /usr/local/sbin/aenv-paused-recovery \
  --store /var/lib/aenv/persisted-sandboxes reconcile
```

`reconcile` is non-destructive: it rebuilds only missing or corrupt index
entries from valid manifests. Review `list` output before any removal.

To deliberately discard one quarantined item and its tracked artifacts:

```sh
sudo /usr/local/sbin/aenv-paused-recovery \
  --store /var/lib/aenv/persisted-sandboxes \
  purge paused-<id> --yes
```

`purge` is irreversible and is the only automated destructive path for
quarantined paused data.

## Refused preservation

When `AENV_PRESERVATION_SOCKET` is configured, the local socket accepts `status`
and `prepare` followed by a newline. It is mode 0600 and intended for the host
administrator/service account. `prepare` returns protocol version, success or
failure, the failing phase, and guest states. A client disconnect or timeout
does not cancel preservation and never authorizes shutdown.

A capacity refusal reports required and available bytes/inodes, headroom, and
largest state consumers. Increase capacity or review reference-aware cleanup;
do not unlink live disk layers or recovery backups. A failed checkpoint keeps
the runtime owner and prevents daemon cleanup. Signal-driven shutdown leaves
the API listening on failure. The supplied systemd service has no stop timeout
or SIGKILL escalation. Resolve the cause and retry preparation before restarting.

ENOSPC may occur after preflight because the checks do not reserve disk space.
Snapshot export copies the writable upper instead of sealing/replacing it.
Artifact data is synced before the Prepared manifest, recovery marker, committed
manifest, and authoritative index; the marker is cleared only after index
acknowledgement. A partial new generation never becomes the current index.
Ambiguous publication remains quarantined for explicit recovery.
