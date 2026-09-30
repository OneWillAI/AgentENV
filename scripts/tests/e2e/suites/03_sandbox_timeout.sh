#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SUITE_DIR}/../lib/helpers.sh"
init_suite "03_timeout"

log "Suite: Sandbox Timeout / TTL"

# -- Create sandbox with timeout --
sandbox_id=$(create_sandbox "$AENV_TEMPLATE_ID" 60); _sync_http
assert_status "$HTTP_STATUS" "201" "create sandbox for timeout tests"
assert_not_empty "$sandbox_id" "sandboxID present"
track_sandbox "$sandbox_id"
wait_for_sandbox_state "$sandbox_id" "running" 30

# -- Update timeout via POST /timeout --
api_post "/sandboxes/${sandbox_id}/timeout" '{"timeout":120}'
assert_status "$HTTP_STATUS" "204" "POST /timeout returns 204"

# -- Extend timeout via POST /refreshes (must be >= current timeout) --
api_post "/sandboxes/${sandbox_id}/refreshes" '{"duration":300}'
assert_status "$HTTP_STATUS" "204" "POST /refreshes returns 204"

# Zero is an explicit no-expiration policy, including on an existing VM.
api_post "/sandboxes/${sandbox_id}/timeout" '{"timeout":5}'
api_post "/sandboxes/${sandbox_id}/timeout" '{"timeout":0}'
assert_status "$HTTP_STATUS" "204" "clear an existing expiration"
api_post "/sandboxes/${sandbox_id}/refreshes" '{"duration":1}'
sleep 7
api_get "/sandboxes/${sandbox_id}"
assert_json_field "$HTTP_BODY" '.state' "running" "refresh does not expire an unlimited sandbox"
assert_json_field "$HTTP_BODY" '(.endAt | split("-")[0] | tonumber) > 2060' "true" "no-expiration endAt representation"
api_post "/sandboxes/${sandbox_id}/pause" '{}'
assert_status "$HTTP_STATUS" "204" "manual pause still works without expiration"
api_post "/sandboxes/${sandbox_id}/connect" '{"timeout":0}'
assert_status "$HTTP_STATUS" "201" "resume without expiration"
api_get "/sandboxes/${sandbox_id}"
assert_json_field "$HTTP_BODY" '(.endAt | split("-")[0] | tonumber) > 2060' "true" "resume preserves unlimited lifetime"
unlimited_id=$(create_sandbox "$AENV_TEMPLATE_ID" 0); _sync_http
assert_status "$HTTP_STATUS" "201" "create without expiration"
track_sandbox "$unlimited_id"
api_get "/sandboxes/${unlimited_id}"
assert_json_field "$HTTP_BODY" '(.endAt | split("-")[0] | tonumber) > 2060' "true" "create accepts zero TTL"
delete_sandbox "$unlimited_id"

# -- Verify auto-pause --
# Use a 5-second timeout. The sandbox takes ~1s to boot, so it should be
# auto-paused around 5s after creation. We poll for up to 20s.
short_id=$(create_sandbox "$AENV_TEMPLATE_ID" 5); _sync_http
assert_status "$HTTP_STATUS" "201" "create short-lived sandbox"
assert_not_empty "$short_id" "short sandbox ID present"
track_sandbox "$short_id"
wait_for_sandbox_state "$short_id" "running" 30

log "Waiting for auto-pause (up to 20s) ..."
# The auto-evict task pauses expired sandboxes (not deletes).
if wait_for_sandbox_state "$short_id" "paused" 20; then
  _pass "short-lived sandbox was auto-paused after TTL"
else
  _fail "short-lived sandbox was auto-paused after TTL" "paused" "still running"
fi

# Clean up the long-lived sandbox
delete_sandbox "$sandbox_id"

suite_summary "03_timeout"
