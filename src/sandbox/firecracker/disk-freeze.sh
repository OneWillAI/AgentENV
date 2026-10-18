#!/bin/sh
# Runs through envd as root. One detached owner holds the lease lock; callers
# request thaw through /run rather than waiting behind a blocked freeze syscall.
set -eu
action=$1
token=$2
case "$token" in ''|*[!a-zA-Z0-9-]*) exit 2 ;; esac
base=/run/agentenv-disk-freeze
lease=/run/agentenv-disk-branch.lease
lock=/run/agentenv-disk-branch.lock
# mkdir -p can request a write on a frozen ancestor even when the path exists.
test -d "$base" || mkdir -p "$base"
state=$base/$token

case "$action" in
    freeze|freeze-stop)
        for tool in fsfreeze flock setsid stat; do command -v "$tool" >/dev/null; done
        test "$(stat -f -c %T /run)" = tmpfs
        # Do not reuse tokens: a delayed caller must never thaw a later freeze.
        mkdir "$state"
        worker=$(cat <<'WORKER'
set -eu
base=$1 lease=$2 lock=$3 state=$4 token=$5 action=$6
exec 9>"$lock"
flock -n 9 || { touch "$state/failed"; exit 1; }
test ! -e "$lease" || { touch "$state/failed"; exit 1; }
# Reap only the prior completed owner's state; an active lease is never removed.
if test -f "$base/previous"; then
    previous=$(cat "$base/previous")
    case "$previous" in ''|*[!a-zA-Z0-9-]*) exit 1 ;; esac
    test "$previous" = "$token" || rm -rf "$base/$previous"
fi
printf '%s' "$token" >"$base/previous"
printf '%s' "$token" >"$lease"
# No child inherits ownership of the lock. The supervisor stays independent of
# both the envd RPC and the freeze child, including during freeze acquisition.
(
    if fsfreeze --freeze /; then touch "$state/frozen";
    else touch "$state/failed"; fi
) 9>&- &
freeze_pid=$!
elapsed=0
expired=false
while :; do
    if test -e "$state/request-thaw" || test -e "$state/failed"; then break; fi
    if test ! -e "$state/frozen" && test "$elapsed" -ge 10; then expired=true; break; fi
    if test "$action" = freeze && test "$elapsed" -ge 60; then expired=true; break; fi
    sleep 1
    elapsed=$((elapsed + 1))
done
if "$expired"; then touch "$state/expired"; fi
# Attempt thaw even if freeze acquisition is still pending. A late successful
# freeze must be followed by another thaw before releasing ownership.
freeze_done=false
if test -e "$state/frozen"; then freeze_done=true; fi
first_thaw=false
if fsfreeze --unfreeze / 9>&-; then first_thaw=true; fi
wait "$freeze_pid" || true
if test -e "$state/frozen"; then
    if ! "$freeze_done" || ! "$first_thaw"; then
        if ! fsfreeze --unfreeze / 9>&-; then
            touch "$state/recovery-failed"
            exit 1
        fi
    fi
elif ! "$first_thaw"; then
    touch "$state/recovery-failed"
    exit 1
fi
rm "$lease"
if "$expired" || test -e "$state/failed"; then touch "$state/failed";
else touch "$state/thawed"; fi
WORKER
)
        setsid /bin/sh -c "$worker" freeze-owner "$base" "$lease" "$lock" "$state" "$token" "$action" </dev/null >/dev/null 2>&1 &
        attempts=0
        while test ! -e "$state/frozen"; do
            test ! -e "$state/failed" && test ! -e "$state/expired" || exit 1
            attempts=$((attempts + 1))
            test "$attempts" -lt 13 || exit 1
            sleep 1
        done
        test ! -e "$state/expired" && test ! -e "$state/thawed" && test ! -e "$state/failed"
        ;;
    thaw)
        test -d "$state"
        # A failed thaw leaves the lease in place. Once its owner has exited,
        # an explicit retry may recover it; never clear exclusion on failure.
        if test -e "$state/recovery-failed"; then
            (
                exec 9>"$lock"
                flock -n 9
                test "$(cat "$lease")" = "$token"
                fsfreeze --unfreeze /
                rm "$lease" "$state/recovery-failed"
                touch "$state/thawed"
            )
        fi
        touch "$state/request-thaw"
        attempts=0
        while test ! -e "$state/thawed"; do
            test ! -e "$state/failed" && test ! -e "$state/expired" && test ! -e "$state/recovery-failed" || exit 1
            attempts=$((attempts + 1))
            test "$attempts" -lt 13 || exit 1
            sleep 1
        done
        test ! -e "$state/expired" && test ! -e "$state/failed"
        ;;
    *) exit 2 ;;
esac
