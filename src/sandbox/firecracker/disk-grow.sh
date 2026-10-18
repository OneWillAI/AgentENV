#!/bin/sh
# Run as root through envd. Only the mounted, whole-device ext4 root is supported.
# Freeze/thaw is owned by disk-freeze.sh; resize2fs must run after thaw.
set -eu
action=$1
desired=$2
case "$desired" in ''|*[!0-9]*) exit 2 ;; esac
test "$desired" -gt 0
test "$((desired % 1048576))" -eq 0
for tool in findmnt blockdev resize2fs fsfreeze flock readlink; do
    command -v "$tool" >/dev/null
done
test "$(findmnt -rn -o FSTYPE --target /)" = ext4
case ",$(findmnt -rn -o OPTIONS --target /)," in
    *,rw,*) ;;
    *) echo 'root filesystem is not writable' >&2; exit 1 ;;
esac
major_minor=$(findmnt -rn -o MAJ:MIN --target /)
test -d "/sys/dev/block/$major_minor"
test ! -e "/sys/dev/block/$major_minor/partition"
device=$(readlink -f "/dev/block/$major_minor")
test -b "$device"
test "$(stat -f -c %T /run)" = tmpfs

case "$action" in
    preflight)
        test ! -e /run/agentenv-disk-branch.lease
        # Check before irreversible backing growth. The kernel cannot resize
        # sparse_super2 filesystems online, even though it can mount them.
        header=$(LC_ALL=C dumpe2fs -h "$device" 2>/dev/null)
        features=$(printf '%s\n' "$header" | awk '/^Filesystem features:/ {for (i=3; i<=NF; i++) printf "%s ", $i}')
        test -n "$features"
        case " $features " in
            *' sparse_super2 '*)
                echo 'root filesystem uses sparse_super2; online resize is unsupported' >&2
                exit 1
                ;;
        esac
        current=$(blockdev --getsize64 "$device")
        test "$desired" -ge "$current" || {
            echo 'disk shrink is not supported' >&2; exit 1;
        }
        printf '%s\n' "$current"
        ;;
    capacity)
        # Virtio's config interrupt reaches the guest asynchronously.
        attempts=0
        while test "$(blockdev --getsize64 "$device")" -ne "$desired"; do
            attempts=$((attempts + 1))
            test "$attempts" -lt 10 || {
                echo 'guest block capacity did not reach requested size' >&2; exit 1;
            }
            sleep 1
        done
        ;;
    filesystem)
        test ! -e /run/agentenv-disk-branch.lease
        test "$(blockdev --getsize64 "$device")" -eq "$desired"
        # resize2fs detects this mounted ext4 and uses online resize ioctls.
        # Specify the target explicitly; never use an offline backend tool.
        exec resize2fs "$device" "$((desired / 1024))K"
        ;;
    *) exit 2 ;;
esac
