# Maintained OneWill fork patch series

The authoritative integration branch is `codex/upstream-patch-series`, based directly
on upstream `04f87864da78d3fb3c2f96bf6a2b719017edc843`. Each future integration
starts from its selected exact upstream target and replays the maintained fork
series as ordinary commits. Drop patches absorbed upstream, adapt contracts to
upstream APIs, and validate the resulting source and runtime behavior. Do not
merge the old integration history into this branch.

## Retained patches

| Patch | Purpose and dependency | Eventual destination |
| --- | --- | --- |
| `db27c93` renewable GCS authentication | Object-store and OverlayBD token renewal, credential configuration and OSS resolution; upstream base only. | Generic renewable credential provider can move upstream; OneWill credential selection can become supported backend configuration. |
| `4129143` checkpoint export and daemon exit | Non-destructive export preserves live writable layers on copy/allocation failure; wait for the owned daemon to exit before releasing devices. Builds on backend support in patch 1. | Generic storage safety belongs upstream, not an external lifecycle hook. |
| `7ac4c16` durable lifecycle, preservation and recovery | Depends on patches 1–2. Durable create idempotency, cancellation-safe operations, publication/stop proof, failed-launch and terminal-capture retention, reference-aware GC, recovery markers and root-only recovery tooling. Preserves tools/kernel/Firecracker identities, disk branches, authentication/network policy and extension contracts while incorporating upstream volume/attached-drive and snapshot APIs. Includes explicit cold-boot upper policy alongside the retained recovery path. | Durability, stop proof, retention and recovery primitives should move upstream. Product disk-branch/discovery policy and extension payloads may move to supported extensions only when those APIs preserve the same guarantees. |
| `80d69a1` explicit memory-restore migration | Depends on patch 3. Opt-in immutable pure-log memory checkpoint → fresh hybrid upper; retains RAM, tools, identity and source checkpoint. Rejects writable or inconsistent sources. | Generic explicit restore policy can move upstream; deployment opt-in stays in Hambody. |
| `023ce57` isolated validation | Depends on patches 1–4. Failure/capability/install tests, physical-allocation workload, pinned MinIO test mirror support and reproducible Rust toolchain selection. | Generic test isolation and storage tests can move upstream; mirror choice and toolchain pin remain release/test configuration. |

The lifecycle patch is deliberately coupled: publication, retained references,
recovery records and device teardown share ownership contracts. Splitting those
contracts into individually unsafe intermediate implementations adds no useful
review boundary. The cold-boot policy accompanies a path absent upstream; the
memory-restore migration remains independently reviewable.

## Equivalence and retained references

The earlier integration remains at `codex/upper-reuse-upstream`, commit
`7c4b2d5e113aab45e6136e6827458dbd36992b6b`, and [PR #2](https://github.com/OneWillAI/AgentENV/pull/2)
is retained as a superseded reference. At `023ce57`, `git diff --exit-code
7c4b2d5 023ce57` passes: the entire tree is identical, including production code,
generated APIs, tests, build configuration and documentation. The subsequent
strategy-documentation commit adds only this document and its navigation entry.
There are no intentional production differences.

Already-upstream backed-zero and discard/reuse commits are inherited from the
base, not replayed. Merge commits and merge-resolution-only commits are omitted;
necessary API adaptations appear with their owning retained patch. The earlier
standalone Clippy corrections are folded into the affected implementations.

Use both `git range-diff 04f8786..7c4b2d5 04f8786..023ce57` and tree diffs.
Range-diff excludes merge commits and cannot establish equivalence for regrouped
patches; the tree comparison and relevant Linux tests are required. Retain prior
raw validation evidence when bytes are unchanged, identify its exact revision,
and run final replacement checks and its own signed release pipeline. Tree
identity is not evidence of successful real-VM migration or staging acceptance.

Never force-push over shared branches or delete references needed by release
pins. Preserve released commits permanently through retained branches/tags and
release records. A later series uses a new branch; earlier release references
remain reachable. Keep Hambody pin changes separate, after replacement
validation. Candidate manifests bind exact AgentENV/Hambody/Hamsite revisions;
a build from a superseded tuple must not be substituted for the replacement.

The prior build `upper-reuse-20260926` / `efcb975f599d-20260926214518-9c75f648`
completed successfully, producing manifest SHA-256
`5b1f6adfc6824e1e63b28ddb43c188c9dc69ac6d189c0a2e2dd2ba2659842cda`.
It is reference evidence only and must not be staged for this restructuring.
Dev and production deployment still require separate manifest-bound approval.

## Replacement validation

On `onewill-builder`, the replacement source at `059accb` passed workspace
formatting, `cargo clippy --locked --workspace --all-targets --all-features --
-D warnings`, and `cargo test --locked -p agentenv --lib` (972 passed, four
capability tests ignored in the ordinary-user run). Checks ran as
`onewill-builder` with isolated state and Rust 1.97.1. The four capability tests
passed in the earlier isolated capability run on the identical production tree.
This documentation update changes no build inputs or production code. Real VM
migration and replacement-manifest staging acceptance remain separate gates.
