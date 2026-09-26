#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/../lib/common.sh"
if [[ ! -f "$COMMON_SH" ]]; then
    echo "Missing helper: ${COMMON_SH}" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/wait.sh"
LOG_TAG=TEST

require_cmd docker
require_cmd timeout
require_cmd cargo

DOCKER_CMD=(docker)
if ! docker info >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
        DOCKER_CMD=(sudo docker)
        warn "Docker requires sudo; using sudo for Docker commands."
    else
        die "Docker daemon not available. Start Docker or ensure your user can access it."
    fi
fi

CONTAINER_NAME="${ENVD_CONTAINER_NAME:-envd}"
IMAGE="${ENVD_IMAGE:-ghcr.io/lsx-s-software/envd-debug:latest}"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
PORTS_RAW="${ENVD_PORTS:-49983 2345 9999 8000 8001}"
PORTS_RAW="${PORTS_RAW//,/ }"
READY_PORT="${ENVD_READY_PORT:-49983}"
START_TIMEOUT_SECS="${ENVD_START_TIMEOUT_SECS:-120}"

cleanup() {
    log "Stopping envd container..."
    "${DOCKER_CMD[@]}" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

# Ensure no pre-existing envd container interferes
"${DOCKER_CMD[@]}" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Start envd in a Docker container
docker_args=(
    --name "$CONTAINER_NAME"
    --platform "$PLATFORM"
    --privileged
    --cgroupns=host
    --rm
    -d
)

IFS=$' \t\n' read -r -a PORTS <<< "$PORTS_RAW"
for port in "${PORTS[@]}"; do
    [[ -n "$port" ]] || continue
    docker_args+=(-p "${port}:${port}")
done

docker_args+=("$IMAGE" /usr/bin/envd -isnotfc)

log "Starting envd container..."
"${DOCKER_CMD[@]}" run "${docker_args[@]}"

# Wait for envd to start
log "Waiting for envd to be ready on port ${READY_PORT}..."
envd_is_ready() {
    if ! "${DOCKER_CMD[@]}" ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
        return 2
    fi

    if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/${READY_PORT}" 2>/dev/null; then
        return 0
    fi

    return 1
}

if ! wait_until "${START_TIMEOUT_SECS}" envd_is_ready; then
    warn "Timeout waiting for envd to start."
    "${DOCKER_CMD[@]}" logs "$CONTAINER_NAME" || true
    exit 1
fi

log "envd is ready. Running tests..."
cargo test -p envd
