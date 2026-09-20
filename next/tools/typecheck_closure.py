"""Enforce the pinned mypy boundary and its exact reviewed diagnostic baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "migration" / "m10_16_typing_baseline.json"
PINNED_VERSION = "2.3.1"
SCOPES = ("src/claasp_next", "tests", "tools", "docs/conf.py")
DIAGNOSTIC = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+):(?P<column>\d+): error: "
    r"(?P<message>.*)  \[(?P<code>[-\w]+)\]$"
)
SUPPRESSION = re.compile(r"#\s*(?:type:\s*ignore|mypy:)")


def run_mypy() -> tuple[str, list[dict[str, object]]]:
    """Run the configured checker and return its version and canonical errors."""

    version_run = subprocess.run(
        [sys.executable, "-m", "mypy", "--version"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    version = version_run.stdout.strip()
    if not version.startswith(f"mypy {PINNED_VERSION} "):
        raise RuntimeError(f"expected mypy {PINNED_VERSION}, found {version!r}")
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", "pyproject.toml"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.stderr:
        raise RuntimeError(f"mypy wrote unexpected stderr:\n{result.stderr}")
    diagnostics = []
    unparsed_errors = []
    for line in result.stdout.splitlines():
        match = DIAGNOSTIC.match(line)
        if match:
            item = match.groupdict()
            diagnostics.append(
                {
                    "path": item["path"],
                    "line": int(item["line"]),
                    "column": int(item["column"]),
                    "code": item["code"],
                    "message": item["message"],
                }
            )
        elif ": error:" in line:
            unparsed_errors.append(line)
    if unparsed_errors:
        raise RuntimeError("unparsed mypy errors:\n" + "\n".join(unparsed_errors))
    if result.returncode not in ({0} if not diagnostics else {1}):
        raise RuntimeError(f"mypy exited {result.returncode}:\n{result.stdout}")
    diagnostics.sort(
        key=lambda item: (
            str(item["path"]),
            int(item["line"]),
            int(item["column"]),
            str(item["code"]),
            str(item["message"]),
        )
    )
    return version, diagnostics


def suppression_violations() -> list[str]:
    """Return unregistered inline mypy suppression directives."""

    violations = []
    for scope in SCOPES:
        target = ROOT / scope
        paths = [target] if target.is_file() else sorted(target.rglob("*.py"))
        for path in paths:
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if SUPPRESSION.search(line):
                    violations.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}")
    return violations


def build_baseline(version: str, diagnostics: list[dict[str, object]]) -> dict[str, object]:
    """Build deterministic baseline metadata from canonical diagnostics."""

    by_scope: Counter[str] = Counter({scope: 0 for scope in SCOPES})
    by_code: Counter[str] = Counter()
    for item in diagnostics:
        path = str(item["path"])
        scope = next((candidate for candidate in SCOPES if path.startswith(candidate)), "other")
        by_scope[scope] += 1
        by_code[str(item["code"])] += 1
    return {
        "schema_version": 1,
        "mypy_version": PINNED_VERSION,
        "scope": list(SCOPES),
        "diagnostic_count": len(diagnostics),
        "counts_by_scope": dict(sorted(by_scope.items())),
        "counts_by_code": dict(sorted(by_code.items())),
        "inline_suppression_exceptions": [],
        "diagnostics": diagnostics,
        "version_evidence": version,
    }


def diagnostic_identity(item: dict[str, object]) -> str:
    """Return the architecture-stable identity of one mypy diagnostic.

    Mypy can report different display columns for the same expression when its
    compiled parser differs between architectures.  Columns remain useful
    evidence in the baseline, but are therefore not part of regression
    identity.
    """

    return json.dumps(
        {field: item[field] for field in ("path", "line", "code", "message")},
        sort_keys=True,
    )


def validate_baseline(
    baseline: dict[str, object], current: dict[str, object]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return new and stale diagnostics relative to the committed authority."""

    if baseline.get("schema_version") != 1:
        raise ValueError("typing baseline schema_version must be 1")
    if baseline.get("mypy_version") != PINNED_VERSION:
        raise ValueError("typing baseline has the wrong pinned mypy version")
    if baseline.get("scope") != list(SCOPES):
        raise ValueError("typing baseline has stale checked scopes")
    if baseline.get("inline_suppression_exceptions") != []:
        raise ValueError("inline typing suppressions are not permitted")
    recorded = baseline.get("diagnostics")
    if not isinstance(recorded, list):
        raise ValueError("typing baseline diagnostics must be a list")
    recorded_by_key = {diagnostic_identity(item): item for item in recorded}
    if len(recorded_by_key) != len(recorded):
        raise ValueError("typing baseline contains duplicate diagnostics")
    rebuilt = build_baseline(str(baseline.get("version_evidence", "")), recorded)
    for field in ("diagnostic_count", "counts_by_scope", "counts_by_code"):
        if baseline.get(field) != rebuilt[field]:
            raise ValueError(f"typing baseline has stale {field}")
    current_items = current["diagnostics"]
    if not isinstance(current_items, list):
        raise ValueError("current diagnostics must be a list")
    current_by_key = {diagnostic_identity(item): item for item in current_items}
    return (
        [current_by_key[item] for item in sorted(current_by_key.keys() - recorded_by_key.keys())],
        [recorded_by_key[item] for item in sorted(recorded_by_key.keys() - current_by_key.keys())],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="rewrite the reviewed baseline")
    parser.add_argument("--check", action="store_true", help="reject new or stale diagnostics")
    args = parser.parse_args(argv)
    if args.write == args.check:
        parser.error("select exactly one of --write or --check")
    suppressions = suppression_violations()
    if suppressions:
        print("unregistered inline typing suppressions:", file=sys.stderr)
        print("\n".join(suppressions), file=sys.stderr)
        return 1
    version, diagnostics = run_mypy()
    current = build_baseline(version, diagnostics)
    if args.write:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {len(diagnostics)} diagnostics to {BASELINE.relative_to(ROOT)}")
        return 0
    if not BASELINE.exists():
        print(f"missing typing baseline: {BASELINE.relative_to(ROOT)}", file=sys.stderr)
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    try:
        new, stale = validate_baseline(baseline, current)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if new or stale:
        print(f"typing baseline mismatch: {len(new)} new, {len(stale)} stale", file=sys.stderr)
        for label, items in (("new", new), ("stale", stale)):
            for item in items[:20]:
                print(f"{label}: {item}", file=sys.stderr)
        return 1
    print(f"typing closure passes: {len(diagnostics)} reviewed diagnostics, 0 suppressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
