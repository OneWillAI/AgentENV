# Disk branching and runtime discovery

These downstream control-plane interfaces run behind the same private network
boundary as the sandbox API. They do not add end-user authentication. Do not
expose the runtime listener directly to the Internet.

`POST /sandboxes/{sandbox_id}/disk-branch` accepts JSON
`{"idempotencyKey":"caller-owned-exact-key"}` and returns
`{"image":"overlaybd-config:/.../image.json"}`. A source must be running.
The key is optional; omission creates a new branch each time. Supplied keys must
be nonempty and at most 1024 UTF-8 bytes. Their contents are not normalized.
Keys are scoped to the source sandbox, and retries replay the first committed
branch rather than taking a new copy of subsequent writes. Invalid keys return
400, missing sources 404, non-running sources 409, and publication failures 500.
The API key/admin token header requirement is unchanged from the existing API;
network isolation remains essential.

The operation briefly pauses Firecracker, copies the writable disk layer, and
resumes the source. It does not copy running processes or unsynced application
buffers. Cold-create a new sandbox using the returned image to obtain an
independent writable upper layer. Callers requiring an application-consistent
copy must flush the application's data before requesting a branch.

## Publication and retries

Artifacts live beneath `<firecracker.work_dir>/managed-snapshots/disk-branches`
(or the runtime's temporary work directory when none is configured). SHA-256
identities cover a versioned domain, source UUID, and exact retry key. A stable
OS file lock serializes concurrent publication, including distinct server
processes using the same root. The source lifecycle lock also excludes pause,
delete and other operations on that handle during disk copying.

A branch becomes usable only after every artifact is synced, its `branch.ref`
marker is atomically installed, and the containing directories are synced.
Marker read/write failures are errors, never success. A replay rechecks and
syncs the committed tree. The image resolver requires canonical containment
beneath the configured root and a marker naming that exact image. Similar path
names in other directories, symlinks escaping the root, and unfinished copies
cannot be used as images.

An interrupted copy without a marker is removed on the next retry under its
publication lock. A published branch is immutable. Legacy branch directories
using the old lossy key names are not accepted as newly resolved images; this
change does not delete those directories or retained paused records.

## Retention and cleanup

Published branches are retained indefinitely, including after source deletion.
Their disk layers can still be referenced by children and by later snapshots;
source deletion is not evidence that a branch is unused. Durable image-cache
holds also protect the branch's local-only lower layers from collection. A
failed publication can conservatively retain such a hold; a retry replaces it. There is deliberately
no age-based or source-deletion garbage collector for published branches.

For manual reclamation, stop the runtime and confirm that every sandbox,
paused record, exported snapshot and dependent branch referencing the target
has been retired. Back up retained data before removing a branch directory.
Never delete `.locks` while any runtime process can be running: replacing a
lock inode defeats serialization. If dependency retirement cannot be proved,
retain the artifact. This policy trades disk use for preservation of children
and paused generations; automated reference-counted collection is not included.

Tests use real files and OS locks to cover replay after reopening, incomplete
attempt cleanup, immutable publication, key/source separation and managed-root
validation. Hosted Firecracker acceptance must additionally prove file copying,
write/process independence, and child survival after parent deletion.

## Discovery hooks

`GET /sandboxes/{sandbox_id}/host-interaction-ip` returns
`{"hostInteractionIp":"169.254.0.21"}` for a live route (404 for a missing
sandbox, 409 while paused or otherwise unavailable). The lookup supplies the host-side address of a sandbox's
network slot. Runtime custom-extension parameters include the Firecracker PID
when available, so the hosted extension can configure that VM's network
namespace. Both values are runtime-local diagnostics/routing inputs; neither is
an end-user authorization credential.
