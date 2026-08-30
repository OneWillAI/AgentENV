#!/usr/bin/env python3
"""Enforce a cyclomatic-complexity ceiling on branch-owned first-party code.

Ownership is diff-aware: a function is checked only when its current line span
intersects a change relative to the configured base ref. Only generated/vendor
code is excluded. Rust, Python, and shell are analyzed in-process. Go uses the
standard-library Go AST, while JavaScript and TypeScript use a pinned ESTree
parser. Complexity is McCabe-style: one base path plus decisions and boolean
short-circuit operators.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


LIMIT = int(os.environ.get("AENV_COMPLEXITY_LIMIT", "15"))
BASE_REF = os.environ.get("AENV_COMPLEXITY_BASE_REF", "origin/main")
GENERATED_PARTS = {"generated", "target", "vendor"}
GO_SUFFIXES = {".go"}
JAVASCRIPT_SUFFIXES = {
    ".cjs",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".ts",
    ".tsx",
}
SUPPORTED_SUFFIXES = {".rs", ".py", ".sh"} | GO_SUFFIXES | JAVASCRIPT_SUFFIXES
GENERATED_NAMES = (
    re.compile(r"(?:^|[._-])generated(?:[._-]|$)"),
    re.compile(r"\.pb\.go$"),
    re.compile(r"\.min\.js$"),
)
TYPESCRIPT_ESTREE_PACKAGE = "@typescript-eslint/typescript-estree@8.42.0"


@dataclass(frozen=True)
class Function:
    name: str
    start_line: int
    end_line: int
    body: str
    score: int | None = None


GO_AST_ANALYZER = r'''package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

type unit struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Score int    `json:"score"`
}

func functionName(node ast.Node) string {
	if declaration, ok := node.(*ast.FuncDecl); ok {
		return declaration.Name.Name
	}
	return "<literal>"
}

func complexity(root ast.Node) int {
	score := 1
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		if node != root {
			switch node.(type) {
			case *ast.FuncDecl, *ast.FuncLit:
				return false
			}
		}
		switch current := node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			score++
		case *ast.CaseClause, *ast.CommClause:
			score++
		case *ast.BinaryExpr:
			if current.Op == token.LAND || current.Op == token.LOR {
				score++
			}
		}
		return true
	})
	return score
}

func analyze(path string) ([]unit, error) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, path, nil, parser.AllErrors)
	if err != nil {
		return nil, err
	}
	result := []unit{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			start := files.Position(node.Pos()).Line
			end := files.Position(node.End()).Line
			result = append(result, unit{path, functionName(node), start, end, complexity(node)})
		}
		return true
	})
	return result, nil
}

func main() {
	result := []unit{}
	for _, path := range os.Args[1:] {
		if path == "--" {
			continue
		}
		units, err := analyze(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(2)
		}
		result = append(result, units...)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
'''


JAVASCRIPT_AST_ANALYZER = r'''const fs = require("fs");
const parser = require("@typescript-eslint/typescript-estree");

const functionTypes = new Set([
  "ArrowFunctionExpression",
  "FunctionDeclaration",
  "FunctionExpression",
]);
const decisionTypes = new Set([
  "CatchClause",
  "ConditionalExpression",
  "DoWhileStatement",
  "ForInStatement",
  "ForOfStatement",
  "ForStatement",
  "IfStatement",
  "SwitchCase",
  "WhileStatement",
]);
const logicalOperators = new Set(["&&", "||", "??"]);
const logicalAssignments = new Set(["&&=", "||=", "??="]);

function children(node) {
  const result = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === "parent" || key === "loc" || key === "range") continue;
    if (Array.isArray(value)) {
      result.push(...value.filter((item) => item && typeof item.type === "string"));
    } else if (value && typeof value.type === "string") {
      result.push(value);
    }
  }
  return result;
}

function addsDecision(node) {
  if (decisionTypes.has(node.type)) return true;
  if (node.type === "LogicalExpression") return logicalOperators.has(node.operator);
  if (node.type === "AssignmentExpression") return logicalAssignments.has(node.operator);
  if (node.type === "AssignmentPattern") return true;
  return (node.type === "CallExpression" || node.type === "MemberExpression") && node.optional;
}

function complexity(root) {
  let score = 1;
  function visit(node) {
    if (node !== root && functionTypes.has(node.type)) return;
    if (addsDecision(node)) score += 1;
    for (const child of children(node)) visit(child);
  }
  visit(root);
  return score;
}

function functionName(node) {
  return node.id && node.id.name ? node.id.name : "<anonymous>";
}

function analyze(path) {
  const source = fs.readFileSync(path, "utf8");
  const tree = parser.parse(source, {
    jsx: /\.[jt]sx$/.test(path),
    loc: true,
    range: true,
    sourceType: "unambiguous",
  });
  const result = [{
    path,
    name: "<module>",
    start: 1,
    end: source.split(/\r?\n/).length,
    score: complexity(tree),
  }];
  function collect(node) {
    if (functionTypes.has(node.type)) {
      result.push({
        path,
        name: functionName(node),
        start: node.loc.start.line,
        end: node.loc.end.line,
        score: complexity(node),
      });
    }
    for (const child of children(node)) collect(child);
  }
  collect(tree);
  return result;
}

const result = process.argv.slice(2).flatMap(analyze);
process.stdout.write(JSON.stringify(result));
'''


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def resolve_base_ref() -> str:
    if subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", BASE_REF],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0:
        return BASE_REF
    raise SystemExit(
        f"complexity base ref {BASE_REF!r} is unavailable; fetch it or set "
        "AENV_COMPLEXITY_BASE_REF"
    )


def excluded(path: Path) -> bool:
    parts = set(path.parts)
    return bool(parts & GENERATED_PARTS) or any(
        pattern.search(path.name) for pattern in GENERATED_NAMES
    )


def changed_lines(base_ref: str) -> dict[Path, set[int]]:
    pathspecs = [f"*{suffix}" for suffix in sorted(SUPPORTED_SUFFIXES)]
    output = git("diff", "--no-ext-diff", "--unified=0", base_ref, "--", *pathspecs)
    result: dict[Path, set[int]] = {}
    current: Path | None = None

    for line in output.splitlines():
        if line.startswith("+++ b/"):
            current = Path(line[6:])
            result.setdefault(current, set())
            continue
        if current is None or not line.startswith("@@"):
            continue
        match = re.search(r"\+(\d+)(?:,(\d+))?", line)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        result[current].update(range(start, start + count))

    for untracked in git(
        "ls-files", "--others", "--exclude-standard", "--", *pathspecs
    ).splitlines():
        path = Path(untracked)
        try:
            line_count = len(path.read_text(encoding="utf-8").splitlines())
        except OSError:
            continue
        result[path] = set(range(1, line_count + 1))

    return result


def run_analyzer(command: list[str], name: str) -> list[dict[str, object]]:
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown failure"
        raise SystemExit(f"{name} complexity analysis failed: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{name} complexity analyzer returned invalid JSON: {error}")
    if not isinstance(payload, list):
        raise SystemExit(f"{name} complexity analyzer returned a non-list result")
    return payload


def group_analyzer_units(
    records: list[dict[str, object]],
) -> dict[Path, list[Function]]:
    result: dict[Path, list[Function]] = {}
    required = {"path", "name", "start", "end", "score"}
    for record in records:
        if not isinstance(record, dict) or not required.issubset(record):
            raise SystemExit("complexity analyzer returned an invalid unit")
        path = Path(str(record["path"]))
        result.setdefault(path, []).append(
            Function(
                str(record["name"]),
                int(record["start"]),
                int(record["end"]),
                "",
                int(record["score"]),
            )
        )
    return result


def go_functions(paths: list[Path]) -> dict[Path, list[Function]]:
    if not paths:
        return {}
    go = shutil.which("go")
    if go is None:
        raise SystemExit(
            "branch-owned Go requires the Go AST complexity analyzer; install "
            "the Go version pinned by services/go.mod"
        )
    with tempfile.TemporaryDirectory(prefix="aenv-go-complexity-") as temp_dir:
        helper = Path(temp_dir) / "main.go"
        helper.write_text(GO_AST_ANALYZER, encoding="utf-8")
        records = run_analyzer(
            [go, "run", str(helper), "--", *(str(path) for path in paths)],
            "Go AST",
        )
    return group_analyzer_units(records)


def javascript_command(helper: Path, paths: list[Path]) -> list[str]:
    npm = shutil.which("npm")
    if npm is None or shutil.which("node") is None:
        raise SystemExit(
            "branch-owned JavaScript/TypeScript requires Node.js and npm for "
            f"the pinned {TYPESCRIPT_ESTREE_PACKAGE} parser"
        )
    shell = (
        'npx_bin="${PATH%%:*}"; '
        'export NODE_PATH="${npx_bin%/.bin}"; '
        'exec node "$@"'
    )
    return [
        npm,
        "exec",
        "--yes",
        f"--package={TYPESCRIPT_ESTREE_PACKAGE}",
        "--",
        "sh",
        "-c",
        shell,
        "aenv-js-complexity",
        str(helper),
        *(str(path) for path in paths),
    ]


def javascript_units(paths: list[Path]) -> dict[Path, list[Function]]:
    if not paths:
        return {}
    with tempfile.TemporaryDirectory(prefix="aenv-js-complexity-") as temp_dir:
        helper = Path(temp_dir) / "analyze.cjs"
        helper.write_text(JAVASCRIPT_AST_ANALYZER, encoding="utf-8")
        records = run_analyzer(javascript_command(helper, paths), "JavaScript AST")
    return group_analyzer_units(records)


def owned_javascript_functions(
    units: list[Function], owned_lines: set[int]
) -> list[Function]:
    module = next((unit for unit in units if unit.name == "<module>"), None)
    functions = [unit for unit in units if unit.name != "<module>"]
    covered_lines = {
        line
        for function in functions
        for line in range(function.start_line, function.end_line + 1)
    }
    top_level_owned = sorted(owned_lines - covered_lines)
    if module is not None and top_level_owned:
        functions.append(
            Function(
                module.name,
                top_level_owned[0],
                top_level_owned[-1],
                "",
                module.score,
            )
        )
    return functions


class RustSourceMasker:
    def __init__(self, source: str) -> None:
        self.source = source
        self.chars = list(source)
        self.index = 0
        self.block_depth = 0
        self.state = "code"
        self.raw_terminator = ""

    def blank(self, index: int) -> None:
        if self.chars[index] != "\n":
            self.chars[index] = " "

    def blank_range(self, start: int, length: int) -> None:
        for offset in range(length):
            self.blank(start + offset)

    def mask_line_comment(self) -> None:
        if self.chars[self.index] == "\n":
            self.state = "code"
        else:
            self.blank(self.index)
        self.index += 1

    def mask_block_comment(self) -> None:
        if self.source.startswith("/*", self.index):
            self.blank_range(self.index, 2)
            self.block_depth += 1
            self.index += 2
        elif self.source.startswith("*/", self.index):
            self.blank_range(self.index, 2)
            self.block_depth -= 1
            self.index += 2
            if self.block_depth == 0:
                self.state = "code"
        else:
            self.blank(self.index)
            self.index += 1

    def mask_string(self) -> None:
        if self.chars[self.index] == "\\":
            length = min(2, len(self.chars) - self.index)
            self.blank_range(self.index, length)
            self.index += length
        elif self.chars[self.index] == '"':
            self.blank(self.index)
            self.state = "code"
            self.index += 1
        else:
            self.blank(self.index)
            self.index += 1

    def mask_raw_string(self) -> None:
        if self.source.startswith(self.raw_terminator, self.index):
            self.blank_range(self.index, len(self.raw_terminator))
            self.index += len(self.raw_terminator)
            self.state = "code"
        else:
            self.blank(self.index)
            self.index += 1

    def char_literal_length(self) -> int:
        start = self.index
        quote = start + 1 if self.source.startswith("b'", start) else start
        if quote >= len(self.source) or self.source[quote] != "'":
            return 0
        cursor = quote + 1
        if cursor >= len(self.source) or self.source[cursor] == "\n":
            return 0
        if self.source[cursor] == "\\":
            cursor += 2
            if self.source.startswith("u{", quote + 2):
                closing = self.source.find("}", quote + 4)
                cursor = closing + 1 if closing >= 0 else cursor
            elif self.source.startswith("x", quote + 2):
                cursor += 2
        else:
            cursor += 1
        return cursor - start + 1 if self.source[cursor : cursor + 1] == "'" else 0

    def mask_code(self) -> None:
        if self.source.startswith("//", self.index):
            self.blank_range(self.index, 2)
            self.state = "line_comment"
            self.index += 2
            return
        if self.source.startswith("/*", self.index):
            self.blank_range(self.index, 2)
            self.state = "block_comment"
            self.block_depth = 1
            self.index += 2
            return
        raw_match = re.match(r'(?:br|r)(#{0,16})"', self.source[self.index :])
        if raw_match:
            self.blank_range(self.index, raw_match.end())
            self.raw_terminator = '"' + raw_match.group(1)
            self.state = "raw_string"
            self.index += raw_match.end()
            return
        if self.source.startswith('b"', self.index):
            self.blank_range(self.index, 2)
            self.state = "string"
            self.index += 2
            return
        if self.chars[self.index] == '"':
            self.blank(self.index)
            self.state = "string"
            self.index += 1
            return
        char_length = self.char_literal_length()
        if char_length:
            self.blank_range(self.index, char_length)
            self.index += char_length
            return
        self.index += 1

    def run(self) -> str:
        while self.index < len(self.chars):
            getattr(self, f"mask_{self.state}")()
        return "".join(self.chars)


def mask_non_code(source: str) -> str:
    """Replace Rust comments and literals with spaces while preserving newlines."""
    return RustSourceMasker(source).run()


def matching_brace(masked: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def function_body_start(masked: str, after_name: int) -> int | None:
    parens = 0
    brackets = 0
    for index in range(after_name, len(masked)):
        char = masked[index]
        if char == "(":
            parens += 1
        elif char == ")":
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif parens == 0 and brackets == 0:
            if char == "{":
                return index
            if char == ";":
                return None
    return None


def rust_functions(source: str) -> list[Function]:
    masked = mask_non_code(source)
    functions: list[Function] = []

    for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", masked):
        opening = function_body_start(masked, match.end())
        if opening is None:
            continue
        closing = matching_brace(masked, opening)
        if closing is None:
            continue
        start_line = masked.count("\n", 0, match.start()) + 1
        end_line = masked.count("\n", 0, closing) + 1
        functions.append(
            Function(match.group(1), start_line, end_line, masked[opening + 1 : closing])
        )

    return functions


class PythonComplexity(ast.NodeVisitor):
    def __init__(self) -> None:
        self.decisions = 0

    def visit_If(self, node: ast.If) -> None:
        self.decisions += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.decisions += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.decisions += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.decisions += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.decisions += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.decisions += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.decisions += len(node.handlers)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.decisions += len(node.cases)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.decisions += 1 + len(node.ifs)
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def python_node_complexity(node: ast.AST) -> int:
    visitor = PythonComplexity()
    if isinstance(node, ast.Lambda):
        visitor.visit(node.body)
    else:
        for statement in getattr(node, "body", []):
            visitor.visit(statement)
    return 1 + visitor.decisions


def python_functions(source: str, owned_lines: set[int]) -> list[Function]:
    tree = ast.parse(source)
    functions: list[Function] = []
    covered_lines: set[int] = set()
    function_nodes = (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
    )

    for node in ast.walk(tree):
        if not isinstance(node, function_nodes):
            continue
        start_line = node.lineno
        end_line = getattr(node, "end_lineno", start_line)
        covered_lines.update(range(start_line, end_line + 1))
        name = getattr(node, "name", "<lambda>")
        functions.append(
            Function(name, start_line, end_line, "", python_node_complexity(node))
        )

    top_level_owned = sorted(owned_lines - covered_lines)
    if top_level_owned:
        module_score = python_node_complexity(tree)
        functions.append(
            Function(
                "<module>",
                top_level_owned[0],
                top_level_owned[-1],
                "",
                module_score,
            )
        )
    return functions


def mask_shell_line(line: str) -> str:
    line = re.sub(r"'(?:[^']*)'", "''", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return re.sub(r"\s+#.*$", "", line)


def shell_complexity(lines: list[str]) -> int:
    decisions = 0
    case_depth = 0
    for raw_line in lines:
        line = mask_shell_line(raw_line)
        decisions += len(re.findall(r"\b(?:if|elif|for|while|until|select)\b", line))
        decisions += len(re.findall(r"&&|\|\|", line))
        if re.search(r"\bcase\b.*\bin\b", line):
            case_depth += 1
        if case_depth and re.match(r"^\s*[^#()]+(?:\|[^()]*)*\)\s*", line):
            decisions += 1
        if re.search(r"\besac\b", line):
            case_depth = max(0, case_depth - 1)
    return 1 + decisions


def shell_functions(source: str, owned_lines: set[int]) -> list[Function]:
    lines = source.splitlines()
    functions: list[Function] = []
    covered_lines: set[int] = set()
    function_start = re.compile(
        r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{\s*$"
    )
    index = 0

    while index < len(lines):
        match = function_start.match(mask_shell_line(lines[index]))
        if not match:
            index += 1
            continue
        closing = index + 1
        while closing < len(lines) and not re.match(
            r"^\s*}\s*$", mask_shell_line(lines[closing])
        ):
            closing += 1
        if closing >= len(lines):
            index += 1
            continue
        start_line = index + 1
        end_line = closing + 1
        covered_lines.update(range(start_line, end_line + 1))
        functions.append(
            Function(
                match.group(1),
                start_line,
                end_line,
                "",
                shell_complexity(lines[index + 1 : closing]),
            )
        )
        index = closing + 1

    top_level_owned = sorted(owned_lines - covered_lines)
    if top_level_owned:
        owned_source = [lines[line - 1] for line in top_level_owned if line <= len(lines)]
        functions.append(
            Function(
                "<script>",
                top_level_owned[0],
                top_level_owned[-1],
                "",
                shell_complexity(owned_source),
            )
        )
    return functions


def complexity(function: Function) -> int:
    if function.score is not None:
        return function.score
    body = function.body
    keyword_decisions = len(re.findall(r"\b(?:if|for|while)\b", body))
    boolean_decisions = len(re.findall(r"&&|\|\|", body))
    match_arms = body.count("=>")
    return 1 + keyword_decisions + boolean_decisions + match_arms


def active_changes(base_ref: str) -> dict[Path, set[int]]:
    result: dict[Path, set[int]] = {}
    for path, lines in changed_lines(base_ref).items():
        if lines and not excluded(path) and path.exists():
            result[path] = lines
    return result


def paths_for_suffixes(
    changes: dict[Path, set[int]], suffixes: set[str]
) -> list[Path]:
    return sorted(path for path in changes if path.suffix in suffixes)


def main() -> int:
    base_ref = resolve_base_ref()
    violations: list[tuple[Path, Function, int]] = []
    changes = active_changes(base_ref)
    go_units = go_functions(paths_for_suffixes(changes, GO_SUFFIXES))
    javascript = javascript_units(
        paths_for_suffixes(changes, JAVASCRIPT_SUFFIXES)
    )

    for path, owned_lines in sorted(changes.items()):
        source = path.read_text(encoding="utf-8")
        if path.suffix == ".rs":
            functions = rust_functions(source)
        elif path.suffix == ".py":
            functions = python_functions(source, owned_lines)
        elif path.suffix == ".sh":
            functions = shell_functions(source, owned_lines)
        elif path.suffix in GO_SUFFIXES:
            functions = go_units.get(path, [])
        elif path.suffix in JAVASCRIPT_SUFFIXES:
            functions = owned_javascript_functions(
                javascript.get(path, []), owned_lines
            )
        else:
            continue
        for function in functions:
            if not any(function.start_line <= line <= function.end_line for line in owned_lines):
                continue
            score = complexity(function)
            if score > LIMIT:
                violations.append((path, function, score))

    if not violations:
        print(f"branch-owned first-party functions satisfy cyclomatic complexity <= {LIMIT}")
        return 0

    print(
        f"branch-owned first-party functions above cyclomatic complexity {LIMIT} "
        f"(base {base_ref}):",
        file=sys.stderr,
    )
    for path, function, score in violations:
        print(
            f"  {path}:{function.start_line} {function.name}: {score}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
