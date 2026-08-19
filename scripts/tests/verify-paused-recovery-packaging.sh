#!/usr/bin/env bash
# Verify that the paused-state recovery tool remains an offline, root-only
# native-host tool. These are static checks because release downloads and
# root-owned installation are intentionally not exercised in unit test jobs.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_workflow="${repo_root}/.github/workflows/release.yml"
installer="${repo_root}/scripts/install.sh"
runtime_dockerfile="${repo_root}/deploy/docker/Dockerfile.agentenv"

bash -n "$installer"

python3 - "$release_workflow" "$installer" "$runtime_dockerfile" <<'PY'
from pathlib import Path
import json
import re
import subprocess
import sys

release, installer, dockerfile = map(Path, sys.argv[1:])
release_text = release.read_text()
installer_text = installer.read_text()
docker_text = dockerfile.read_text()

metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=release.parents[2],
        text=True,
    )
)
agentenv = next(package for package in metadata["packages"] if package["name"] == "agentenv")
if not any(
    target["name"] == "aenv-paused-recovery" and "bin" in target["kind"]
    for target in agentenv["targets"]
):
    raise SystemExit("aenv-paused-recovery is not a buildable AgentENV binary target")

required_release_fragments = (
    "-p agentenv --bin server --bin aenv-paused-recovery",
    'cp target/release/aenv-paused-recovery "$BUNDLE/aenv-paused-recovery"',
    'strip "$BUNDLE/aenv-paused-recovery"',
)
for fragment in required_release_fragments:
    if fragment not in release_text:
        raise SystemExit(f"release workflow no longer stages paused recovery utility: {fragment}")

required_installer_fragments = (
    'RECOVERY_INSTALL_DIR="/usr/local/sbin"',
    'RECOVERY_BINARY_PATH="${RECOVERY_INSTALL_DIR}/aenv-paused-recovery"',
    'sudo install -d -o root -g root -m 0755 "$RECOVERY_INSTALL_DIR"',
)
for fragment in required_installer_fragments:
    if fragment not in installer_text:
        raise SystemExit(f"installer no longer enforces root-only recovery utility installation: {fragment!r}")

if not re.search(
    r'sudo install -o root -g root -m 0700\s*\\\n\s*'
    r'"\$tmp_dir/aenv-paused-recovery" "\$RECOVERY_BINARY_PATH"',
    installer_text,
):
    raise SystemExit("installer no longer installs paused recovery utility root-only")

if "aenv-paused-recovery" in docker_text:
    raise SystemExit(
        "runtime Dockerfile must not package the host-local paused recovery utility"
    )
PY
