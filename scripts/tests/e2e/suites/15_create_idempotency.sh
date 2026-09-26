#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SUITE_DIR}/../lib/helpers.sh"
init_suite "15_create_idempotency"

log "Suite: Create Idempotency"

idempotency_key="e2e-create-$(date +%s%N)"
first_payload=$(jq -nc \
  --arg template "${AENV_TEMPLATE_ID}" \
  --arg key "${idempotency_key}" \
  '{templateID: $template, idempotencyKey: $key, metadata: {first: "1", second: "2"}}')

create_url="${AENV_URL}"
if e2e_mode_is_clustered; then
  create_url=$(candidate_node_urls | head -n 1)
  assert_not_empty "${create_url}" "cluster exposes a node for concurrent create coverage"
fi

first_body_file=$(mktemp)
first_status_file=$(mktemp)
second_body_file=$(mktemp)
second_status_file=$(mktemp)

concurrent_create() {
  local body_file="$1"
  local status_file="$2"
  curl -s -X POST \
    -H "X-API-Key: ${AENV_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "${first_payload}" \
    -o "${body_file}" \
    -w '%{http_code}' \
    "${create_url}/sandboxes" >"${status_file}" 2>/dev/null || true
}

concurrent_create "${first_body_file}" "${first_status_file}" &
first_pid=$!
concurrent_create "${second_body_file}" "${second_status_file}" &
second_pid=$!
wait "${first_pid}" "${second_pid}"

first_status=$(<"${first_status_file}")
first_body=$(<"${first_body_file}")
second_status=$(<"${second_status_file}")
second_body=$(<"${second_body_file}")
rm -f \
  "${first_body_file}" \
  "${first_status_file}" \
  "${second_body_file}" \
  "${second_status_file}"

assert_status "${first_status}" "201" "first concurrent idempotent create returns 201"
assert_status "${second_status}" "201" "second concurrent idempotent create returns 201"
sandbox_id=$(echo "${first_body}" | jq -r '.sandboxID // empty')
concurrent_replay_id=$(echo "${second_body}" | jq -r '.sandboxID // empty')
assert_not_empty "${sandbox_id}" "concurrent idempotent create returns a sandbox ID"
assert_eq "${concurrent_replay_id}" "${sandbox_id}" "concurrent create returns one sandbox"
track_sandbox "${sandbox_id}"

owner_url="${AENV_URL}"
if e2e_mode_is_clustered; then
  owner_url=$(find_sandbox_node_url "${sandbox_id}")
  assert_not_empty "${owner_url}" "idempotent sandbox resolves to its owning node"
fi

equivalent_payload=$(jq -nc \
  --arg template "${AENV_TEMPLATE_ID}" \
  --arg key "${idempotency_key}" \
  '{
    templateID: $template,
    idempotencyKey: $key,
    metadata: {second: "2", first: "1"},
    autoPause: true,
    autoResume: {enabled: false},
    secure: false,
    envVars: {}
  }')
api_post_at "${owner_url}" "/sandboxes" "${equivalent_payload}"
assert_status "${HTTP_STATUS}" "201" "equivalent idempotent replay returns 201"
replayed_id=$(echo "${HTTP_BODY}" | jq -r '.sandboxID // empty')
assert_eq "${replayed_id}" "${sandbox_id}" "equivalent replay returns the original sandbox"

changed_payload=$(echo "${first_payload}" | jq '. + {timeout: 61}')
api_post_at "${owner_url}" "/sandboxes" "${changed_payload}"
assert_status "${HTTP_STATUS}" "400" "changed request with reused idempotency key is rejected"

empty_key_payload=$(jq -nc \
  --arg template "${AENV_TEMPLATE_ID}" \
  '{templateID: $template, idempotencyKey: ""}')
api_post_at "${owner_url}" "/sandboxes" "${empty_key_payload}"
assert_status "${HTTP_STATUS}" "400" "empty idempotency key is rejected"

api_delete_at "${owner_url}" "/sandboxes/${sandbox_id}"
assert_status "${HTTP_STATUS}" "204" "deleting an idempotently-created sandbox succeeds"

api_post_at "${owner_url}" "/sandboxes" "${first_payload}"
assert_status "${HTTP_STATUS}" "201" "proven delete releases the idempotency key"
replacement_id=$(echo "${HTTP_BODY}" | jq -r '.sandboxID // empty')
assert_not_empty "${replacement_id}" "released key creates a replacement sandbox"
assert_not_eq "${replacement_id}" "${sandbox_id}" "released key creates a new sandbox"
track_sandbox "${replacement_id}"

suite_summary "15_create_idempotency"
