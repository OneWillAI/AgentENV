#!/usr/bin/env bash
# Server lifecycle helpers for e2e tests.

if [[ -z "${E2E_SERVER_SH_LOADED:-}" ]]; then
  E2E_SERVER_SH_LOADED=1

  E2E_SERVER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=/dev/null
  source "${E2E_SERVER_LIB_DIR}/../../lib/wait.sh"

  : "${AENV_PORT:=18080}"
  : "${AENV_URL:=http://127.0.0.1:${AENV_PORT}}"
  : "${AENV_API_KEY:=e2e-test-key}"
  : "${SERVER_START_TIMEOUT:=30}"

  _SERVER_PID=""

  start_server() {
    local binary="${1:?usage: start_server <binary> [config_path]}"
    local config="${2:-}"

    local env_vars=(
      "API_ADDR=127.0.0.1:${AENV_PORT}"
      "RUST_LOG=agentenv=info,envd=info"
    )
    [[ -n "$config" ]] && env_vars+=("AENV_CONFIG_PATH=${config}")

    # Kill any stale process on the port
    _kill_port_holder

    local run_cmd=()
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      run_cmd=("${REPO_ROOT}/scripts/run-with-capabilities.sh")
    fi

    log "Starting server on 127.0.0.1:${AENV_PORT} ..."
    "${run_cmd[@]}" env "${env_vars[@]}" "$binary" &
    _SERVER_PID=$!

    if ! kill -0 "$_SERVER_PID" 2>/dev/null; then
      die "Server process exited immediately (PID ${_SERVER_PID})"
    fi

    export AENV_URL AENV_API_KEY
  }

  wait_for_server() {
    local timeout="${1:-$SERVER_START_TIMEOUT}"
    log "Waiting for server at ${AENV_URL}/health (timeout ${timeout}s) ..."
    if wait_until "${timeout}" _server_is_ready; then
      log "Server is ready."
      return 0
    fi
    die "Server failed to become ready within ${timeout}s"
  }

  _server_is_ready() {
    kill -0 "${_SERVER_PID}" 2>/dev/null || return 2
    curl -sf "${AENV_URL}/health" >/dev/null 2>&1 && return 0
    return 1
  }

  _server_port_is_free() {
    ! fuser "${AENV_PORT}/tcp" >/dev/null 2>&1
  }

  # Kill whatever is listening on AENV_PORT.
  _kill_port_holder() {
    if command -v fuser >/dev/null 2>&1; then
      sudo fuser -k "${AENV_PORT}/tcp" 2>/dev/null || true
      wait_until 5 _server_port_is_free || true
    fi
  }

  stop_server() {
    # When the server was started via sudo, $! is the sudo PID.
    # Killing it may not propagate, so also kill by port.
    if [[ -n "$_SERVER_PID" ]]; then
      log "Stopping server (PID ${_SERVER_PID}) ..."
      sudo kill "$_SERVER_PID" 2>/dev/null || kill "$_SERVER_PID" 2>/dev/null || true
    fi
    _kill_port_holder
    # Don't wait on the sudo PID (it may already be gone or be an orphan).
    _SERVER_PID=""
  }
fi
