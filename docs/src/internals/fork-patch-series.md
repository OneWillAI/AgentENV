# Maintained OneWill fork patch series

The canonical integration branch is `codex/will-devenv-ssh`, based directly on
exact upstream `04f87864da78d3fb3c2f96bf6a2b719017edc843`. Each future integration
starts from its selected upstream target and replays the maintained fork series.
Drop patches absorbed upstream, adapt contracts to upstream APIs, and validate
the final source and runtime behavior. Released revisions remain reachable.

## Review boundaries

The former large lifecycle commit `7ac4c16` is split into twelve feature slices.
Apply the complete series in order. Shared contracts include interfaces completed
by later slices: these are dependent review boundaries, not independently
build-certified or deployable revisions. Complete Rust methods are kept together;
no temporary implementations were introduced to create artificial build points.
All rewritten commits use William Zhang <17zhangw@gmail.com>.

| Patch | Purpose and dependencies | Eventual destination |
| --- | --- | --- |
| `b0bd8a6b` | Renewable GCS credentials across object backends; upstream base. | Generic credential provider upstream; deployment selection configurable. |
| `8d84585d` | Non-destructive checkpoint export and owned-daemon exit proof; storage/backend support. | Generic storage safety upstream. |
| `e4c2c7eb` | Shared durable record, sync/path and lifecycle interfaces; foundation for later slices. | Generic durability primitives upstream. |
| `bafb88dc` | Create journal, request fingerprints, replay/cancellation, API schemas and tests; shared contracts plus lifecycle integration. | Generic retry semantics upstream. |
| `bedfbbd4` | Checkpoint publication, pause/resume transactions and compact snapshot integration; storage export and contracts. | Generic persistence safety upstream. |
| `30fbca38` | Index reconciliation, interrupted-resume protection, quarantine and host-local recovery; checkpoint records. | Generic recovery upstream; operator policy configurable. |
| `fcf45419` | Typed references, cache holds, retention and capacity preflight; checkpoint/recovery contracts. | Generic retention and capacity upstream. |
| `8a42fc1c` | Preservation socket and guarded shutdown; checkpoints, recovery and stop ownership. | Generic shutdown protocol upstream; rollout policy in Hambody. |
| `8d6f85ea` | Failed-launch/terminal-capture/delete retries and VM/volume retention until proven stop; lifecycle contracts. | Generic ownership safety upstream. |
| `1d0cf680` | Immutable disk branches, publication markers, freeze/thaw and child references; safe export and lifecycle exclusion. | Generic copy primitive upstream; product interface may become an extension. |
| `95ad79ab` | Extension persistence, discovery, readiness and network/proxy compatibility; lifecycle hooks. | Generic hook semantics upstream; OneWill routing in extensions. |
| `c3aedd51` | Tools/kernel/Firecracker identities, snapshot metadata and CPU configuration; runtime/checkpoint contracts. | Generic compatibility validation upstream. |
| `839ec834` | Disk-only recovery/reboot and explicit writable-upper policy; checkpoints, ownership and identities. | Generic recovery and policy upstream. |
| `543e58ae` | Installation, capability and integration-fixture support; preceding runtime features. | Generic packaging upstream; release configuration downstream. |
| `d910113a` | Explicit immutable pure-log memory checkpoint to fresh hybrid upper; full lifecycle series. Retains RAM, tools and identity. | Generic restore policy upstream; opt-in in Hambody. |
| `d8421015` | Isolated failure/capability/storage tests and reproducible build support; preceding features. | Generic tests upstream; mirror/toolchain choices in configuration. |

## Equivalence and permanent references

The entire tree at re-sliced revision
`6380e14f9c6c607074bcdc8486e82a78c17efe48` equals the previously validated revision
`8233f802125d000af17489a928ff5bd4956206e4`; Git tree
`50be38503a5c04eb4c680f2e1fe6983953db3c0b`. This canonical-branch update changes
only this document. There are no intentional production behavior differences.

The previous canonical branch is preserved as `codex/will-devenv-ssh-old` at
`3ec59647845b85c4d823d223c0f4e77e666d10d1`. Earlier integration remains at
`codex/upper-reuse-upstream` / `7c4b2d5`, the first series at
`codex/upstream-patch-series` / `8233f80`, and the re-sliced reference at
`codex/reviewable-patch-series` / `6380e14f`. AgentENV PRs #2 and #3 are closed
references; no replacement PR was created. Renaming the old canonical branch
was explicitly authorized, and did not delete its commits or release references.

Already-upstream backed-zero and discard/reuse fixes are inherited, not replayed.
No merge commits are introduced. Use tree comparisons and
`git range-diff 04f8786..8233f80 04f8786..6380e14f`; regrouping makes range-diff
alone insufficient. Rust parsing checked the five shared files at all twelve
slice boundaries (60 file versions); this is not intermediate type checking.

Preserve released commits permanently through retained branches/tags and signed
release records. Do not overwrite a shared branch without explicit authorization
and preserved references. Candidate manifests bind exact AgentENV/Hambody/Hamsite
revisions. User-authorized Hambody consolidation and a new pin produce a new
source tuple, which requires its own normal signed build and staging acceptance.

## Validation baseline

The unchanged production tree passed Linux formatting, full workspace/all-targets/
all-features Clippy, 972 AgentENV tests and separate capability/storage/failure
checks. Signed candidate manifest
`32cd33215fba67c405e71b859b272589f660bdcc6cbabd19147151c72a4b5150`
passed full staging-2 acceptance, actual cold boot, memory-preserving pure-log to
hybrid migration, host restart and post-stage gateway/sign-in checks. That evidence
remains valid for its original source tuple; a canonical-tip candidate must not
substitute the old manifest for new tuple-bound acceptance. Dev and production
promotion remain separately authorized, manifest-bound actions.
