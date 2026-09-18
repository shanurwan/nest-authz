"""Reproducible static hygiene scan for security-critical source modules."""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PACKAGE = _ROOT / "src" / "nest_authz"
_PURE_MODULES = {
    "applicability.py",
    "approval.py",
    "approver.py",
    "attestation.py",
    "authenticated_delegation.py",
    "binding.py",
    "canonical.py",
    "delegation.py",
    "domain.py",
    "evaluator.py",
    "execution.py",
    "execution_enforcement.py",
    "receipt.py",
    "trusted.py",
}
_PROHIBITED_PURE_IMPORTS = {
    "datetime",
    "http",
    "os",
    "pathlib",
    "pickle",
    "random",
    "requests",
    "secrets",
    "socket",
    "sqlite3",
    "subprocess",
    "time",
    "urllib",
    "uuid",
}
_PROHIBITED_CALLS = {"eval", "exec", "getattr", "hash", "open", "repr"}


def _import_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".", maxsplit=1)[0])
    return roots


def main() -> int:
    failures: list[str] = []
    findings: list[str] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        relative = path.relative_to(_PACKAGE).as_posix()
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imports = _import_roots(tree)

        if relative in _PURE_MODULES:
            for name in sorted(imports & _PROHIBITED_PURE_IMPORTS):
                failures.append(f"{relative}: prohibited pure-core import {name}")

        if relative == "sqlite_execution_store.py" and "sqlite3" in imports:
            findings.append(
                "sqlite_execution_store.py: sqlite3 import is confined to the "
                "infrastructure adapter"
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in _PROHIBITED_CALLS:
                    failures.append(
                        f"{relative}:{node.lineno}: prohibited call {node.func.id}()"
                    )
            if isinstance(node, ast.ExceptHandler):
                catches_all = node.type is None or (
                    isinstance(node.type, ast.Name) and node.type.id == "Exception"
                )
                if catches_all and relative in _PURE_MODULES:
                    failures.append(
                        f"{relative}:{node.lineno}: broad exception handler in pure core"
                    )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "isinstance" and len(node.args) >= 2:
                    checked = node.args[1]
                    if isinstance(checked, ast.Name) and checked.id == "int":
                        failures.append(
                            f"{relative}:{node.lineno}: isinstance(..., int) can accept bool"
                        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    for finding in findings:
        print(f"ACCEPTED: {finding}")
    print("OK: no prohibited dynamic execution or ambient-state access in pure core")
    print("OK: no broad pure-core exception handlers or bool-as-int isinstance checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
