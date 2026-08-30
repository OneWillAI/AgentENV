#!/usr/bin/env bash
# Shared bounded polling helpers for integration and end-to-end tests.

if [[ -z "${AENV_TEST_WAIT_SH_LOADED:-}" ]]; then
  AENV_TEST_WAIT_SH_LOADED=1

  adaptive_poll_sleep() {
    local attempt="${1:-0}"
    local delay

    if ((attempt < 4)); then
      delay=0.05
    elif ((attempt < 10)); then
      delay=0.1
    elif ((attempt < 20)); then
      delay=0.25
    else
      delay=0.5
    fi

    sleep "${delay}"
  }

  # Run a predicate until it succeeds or timeout seconds elapse. A predicate
  # status of 1 means "retry"; status 2 means "stop immediately".
  wait_until() {
    local timeout="${1:?usage: wait_until <timeout-seconds> <predicate> [args...]}"
    shift
    local deadline=$((SECONDS + timeout))
    local attempt=0
    local status

    while true; do
      if "$@"; then
        return 0
      else
        status=$?
      fi

      [[ "${status}" -eq 2 ]] && return 2
      ((SECONDS >= deadline)) && return 1
      adaptive_poll_sleep "${attempt}"
      ((attempt += 1))
    done
  }
fi
