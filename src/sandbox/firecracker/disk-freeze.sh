#!/bin/sh
# Runs through envd as root. /run must be independent of the frozen rootfs.
# Serialize thaw with acquisition: an old watchdog must never thaw a new copy.
set -eu
action=$1
token=$2
lease=/run/agentenv-disk-branch.lease
lock=/run/agentenv-disk-branch.lock

release() (
    flock -x 9
    test -f "$lease" && test "$(cat "$lease")" = "$token" || exit 1
    fsfreeze --unfreeze /
    rm "$lease"
) 9>"$lock"

case "$action" in
    freeze|freeze-stop)
        command -v fsfreeze >/dev/null
        command -v flock >/dev/null
        # A tmpfs lease remains writable while / is frozen. Reject images
        # without it rather than risking an unthawable guest.
        test "$(stat -f -c %T /run)" = tmpfs
        (
            flock -x 9
            test ! -e "$lease"
            printf '%s' "$token" >"$lease"
            # Also recovers a lost RPC or a server exit. Close the inherited
            # lock descriptor and streams before detaching the watchdog.
            # A cold-stop capture keeps its freeze until confirmed VM stop.
            # Its lifecycle owner must explicitly thaw on rollback; a timer
            # must never silently permit writes during disk-only capture.
            if test "$action" = freeze; then
                (sleep 60; release) </dev/null >/dev/null 2>&1 9>&- &
            fi
            if ! fsfreeze --freeze /; then
                rm "$lease"
                exit 1
            fi
        ) 9>"$lock"
        ;;
    thaw) release ;;
    *) exit 2 ;;
esac
