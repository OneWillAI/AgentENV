# Guest kernel EROFS

Hambody toppings (Codex, Claude, Exo, Discord) attach as independent
file-backed **erofs** images with an overlayfs upper. The Firecracker guest
kernel must provide erofs. GCE base images are the **host** kernel only and
do not affect this.

## Current pins

Setup downloads `vmlinux` from [`config/deps_manifest.toml`](../../config/deps_manifest.toml):

| Mode | Key | Artifact |
| --- | --- | --- |
| KVM | `kernel.kvm` | `vmlinux-6.1.175` from kvcache-ai/firecracker `aenv-deps` |
| PVM | `kernel.pvm` | `vmlinux-guest-6.12.33-pvm` |

Those published bits include overlay, squashfs, fuse, and ext4. They do **not**
include the erofs filesystem (only the `-EROFS` errno). Hosted computers cannot
mount topping seeds until a new guest kernel is published.

The fragment to apply is [`config/kernel/erofs-guest.fragment`](../../config/kernel/erofs-guest.fragment):

- `CONFIG_EROFS_FS=y`
- `CONFIG_EROFS_FS_ZIP=y`
- `CONFIG_EROFS_FS_BACKED_BY_FILE=y` (Linux **6.12+**. Vanilla `6.1.175` has
  erofs and ZIP only; `olddefconfig` drops this symbol because the Kconfig
  option does not exist.)

Loop-mount erofs works without file-backed support. File-backed is required so
each topping does not consume a loop device. The KVM guest should follow
current [kernel.org longterm](https://www.kernel.org/) (`6.18.45`), not the
Firecracker 6.1 CI pin.

## Rollout

1. Take the same guest-kernel tree already used for the pin.
2. Merge `config/kernel/erofs-guest.fragment`.
3. Rebuild `vmlinux` on the persistent GCP burst builder (not a Mac).
4. Publish the artifact and bump the `version` / `url` in `deps_manifest.toml`.
5. Roll AgentENV workers so new VMs download the new kernel.
6. Rebuild the default guest template. Existing paused VMs keep the old kernel
   until relaunch.

This is a kernel-config and release change. It does not add an AgentENV
scheduler or disk API. OverlayBD on the worker remains the rootfs snapshot
pool, not the topping attach path.
