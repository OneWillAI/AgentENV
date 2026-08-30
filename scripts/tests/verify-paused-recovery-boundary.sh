#!/usr/bin/env bash
# Exercise the built recovery utility through the same installed-file boundary
# used by an operator. This intentionally does not read release, installer, or
# container source files.
set -euo pipefail

: "${AENV_PAUSED_RECOVERY_BINARY:?set AENV_PAUSED_RECOVERY_BINARY to the built recovery binary}"

if [[ ! -x "${AENV_PAUSED_RECOVERY_BINARY}" ]]; then
  echo "recovery binary is missing or not executable: ${AENV_PAUSED_RECOVERY_BINARY}" >&2
  exit 1
fi

stage_root="$(mktemp -d)"
cleanup() {
  if [[ "$(id -u)" == "0" ]]; then
    rm -rf "${stage_root}"
  else
    sudo rm -rf "${stage_root}"
  fi
}
trap cleanup EXIT

if [[ "$(id -u)" == "0" ]]; then
  privilege=()
else
  privilege=(sudo)
fi

installed="${stage_root}/usr/local/sbin/aenv-paused-recovery"
"${privilege[@]}" install -D -o root -g root -m 0700 \
  "${AENV_PAUSED_RECOVERY_BINARY}" "${installed}"

mode="$(stat -c '%a' "${installed}")"
owner="$(stat -c '%u:%g' "${installed}")"
[[ "${mode}" == "700" ]]
[[ "${owner}" == "0:0" ]]

"${privilege[@]}" "${installed}" --help | grep -Fq 'aenv-paused-recovery'

relative_error="${stage_root}/relative.err"
if "${privilege[@]}" "${installed}" --store relative list 2>"${relative_error}"; then
  echo "relative recovery store unexpectedly succeeded" >&2
  exit 1
fi
grep -Fq -- '--store must be an absolute path' "${relative_error}"

store="${stage_root}/store"
list_output="$("${privilege[@]}" "${installed}" --store "${store}" list)"
[[ "$(jq -c . <<<"${list_output}")" == '[]' ]]

confirmation_error="${stage_root}/confirmation.err"
if "${privilege[@]}" "${installed}" --store "${store}" purge paused-does-not-exist \
  2>"${confirmation_error}"; then
  echo "unconfirmed recovery purge unexpectedly succeeded" >&2
  exit 1
fi
grep -Fq 'refusing destructive purge without --yes' "${confirmation_error}"

if command -v setpriv >/dev/null 2>&1; then
  if "${privilege[@]}" setpriv --reuid=nobody --regid=nogroup --clear-groups \
    "${installed}" --help >/dev/null 2>&1; then
    echo "root-only recovery install was executable by nobody" >&2
    exit 1
  fi
fi
