#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "tree-sitter==0.25.2",
#   "tree-sitter-bash==0.25.1",
#   "tree-sitter-javascript==0.25.0",
# ]
# ///
"""Reject literal sleeps added to first-party test and release coordination."""

from __future__ import annotations

import ast
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Language, Node, Parser
import tree_sitter_bash
import tree_sitter_javascript


ROOT = Path(__file__).resolve().parents[2]
BASE_REF = os.environ.get("AENV_FIXED_WAIT_BASE_REF", "origin/main")
SCOPES = ("scripts", ".github")
JAVASCRIPT_SUFFIXES = {".cjs", ".js", ".mjs"}
SHELL_SUFFIXES = {".bash", ".sh", ".zsh"}
EXEMPT_HELPERS = {Path("scripts/tests/lib/wait.sh")}


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    message: str


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True)


def changed_lines() -> dict[Path, set[int]]:
    if subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", BASE_REF],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        raise SystemExit(f"fixed-wait base ref {BASE_REF!r} is unavailable")
    output = git("diff", "--no-ext-diff", "--unified=0", BASE_REF, "--", *SCOPES)
    result: dict[Path, set[int]] = {}
    current: Path | None = None
    for line in output.splitlines():
        if line.startswith("+++ b/"):
            current = Path(line[6:])
            result.setdefault(current, set())
        elif current is not None and line.startswith("@@"):
            coordinates = line.split("+", 1)[1].split(" ", 1)[0]
            start_text, _, count_text = coordinates.partition(",")
            start = int(start_text)
            count = int(count_text or "1")
            result[current].update(range(start, start + count))
    untracked = git(
        "ls-files", "--others", "--exclude-standard", "--", *SCOPES
    ).splitlines()
    for name in untracked:
        path = Path(name)
        if path.is_file():
            result[path] = set(range(1, len(path.read_text(encoding="utf-8").splitlines()) + 1))
    return result


def source_kind(path: Path) -> str | None:
    if path in EXEMPT_HELPERS or not path.is_file():
        return None
    if path.suffix in JAVASCRIPT_SUFFIXES:
        return "javascript"
    if path.suffix == ".py":
        return "python"
    if path.suffix in SHELL_SUFFIXES:
        return "shell"
    header = path.read_bytes()[:192].split(b"\n", 1)[0]
    if any(shell in header for shell in (b"/sh", b"/bash", b"/zsh")):
        return "shell"
    if b"python" in header:
        return "python"
    return None


def walk(root: Node):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def owned(node: Node, lines: set[int]) -> bool:
    return any(node.start_point.row + 1 <= line <= node.end_point.row + 1 for line in lines)


def shell_violations(parser: Parser, path: Path, lines: set[int]) -> list[Violation]:
    root = parser.parse(path.read_bytes()).root_node
    violations: list[Violation] = []
    for node in walk(root):
        if node.type != "command" or not owned(node, lines):
            continue
        name = node.child_by_field_name("name")
        arguments = [child for child in node.named_children if child.type != "command_name"]
        if name is not None and name.text in {b"sleep", b"usleep"} and arguments:
            argument = arguments[0]
            if argument.type in {"number", "word"} and argument.text[:1].isdigit():
                violations.append(Violation(path, node.start_point.row + 1, "literal shell sleep; use the adaptive wait helper"))
    return violations


def javascript_violations(parser: Parser, path: Path, lines: set[int]) -> list[Violation]:
    root = parser.parse(path.read_bytes()).root_node
    violations: list[Violation] = []
    for node in walk(root):
        if node.type != "call_expression" or not owned(node, lines):
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        values = [] if arguments is None else arguments.named_children
        if function is not None and function.type == "identifier" and function.text == b"sleep" and values and values[0].type == "number":
            violations.append(Violation(path, node.start_point.row + 1, "literal JavaScript sleep; use an event or adaptive deadline"))
    return violations


def python_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    return ""


def python_violations(path: Path, lines: set[int]) -> list[Violation]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        Violation(path, node.lineno, "literal Python sleep; use an event or adaptive deadline")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and node.lineno in lines
        and python_call_name(node) in {"sleep", "time.sleep", "asyncio.sleep"}
        and node.args
        and isinstance(node.args[0], (ast.Constant, ast.UnaryOp))
    ]


def main() -> None:
    bash = Parser(Language(tree_sitter_bash.language()))
    javascript = Parser(Language(tree_sitter_javascript.language()))
    violations: list[Violation] = []
    checked = 0
    for path, lines in sorted(changed_lines().items()):
        kind = source_kind(path)
        if kind == "shell":
            violations.extend(shell_violations(bash, path, lines))
        elif kind == "javascript":
            violations.extend(javascript_violations(javascript, path, lines))
        elif kind == "python":
            violations.extend(python_violations(path, lines))
        else:
            continue
        checked += 1
    if violations:
        raise SystemExit("\n".join(
            f"{item.path}:{item.line}: {item.message}" for item in violations
        ))
    print(f"branch-owned fixed-wait AST check passed ({checked} files)")


if __name__ == "__main__":
    main()
