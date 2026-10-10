"""Validate the complete M10.16 documentation and static-quality authority."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT
MANIFEST = ROOT / "migration" / "m10_16_quality.json"
PUBLIC_API = ROOT / "migration" / "m10_16_public_api.json"
TYPING = ROOT / "migration" / "m10_16_typing_baseline.json"
EXPECTED_SCOPE = ["src/claasp", "tests", "tools", "docs/conf.py"]
EXPECTED_TYPING_BOUNDARIES = [
    "matplotlib",
    "matplotlib.*",
    "numpy",
    "numpy.*",
    "pandas",
    "pandas.*",
    "sklearn",
    "sklearn.*",
    "tensorflow",
    "tensorflow.*",
]
EXPECTED_VERSIONS = {
    "build": "1.3.0",
    "furo": "2025.12.19",
    "mypy": "2.3.1",
    "pytest": "9.1.1",
    "ruff": "0.16.8",
    "sphinx": "9.0.4",
}


def _load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_manifest(manifest: dict[str, object]) -> list[str]:
    """Return deterministic closure violations for one manifest value."""

    errors = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M10.16":
        errors.append("manifest identity or schema is invalid")
    if manifest.get("quality_scope") != EXPECTED_SCOPE:
        errors.append("quality scope is stale")
    if manifest.get("versions") != EXPECTED_VERSIONS:
        errors.append("pinned tool versions are stale")

    evidence = manifest.get("evidence")
    if not isinstance(evidence, list) or evidence != sorted(set(evidence)):
        errors.append("evidence paths must be unique and sorted")
    else:
        for item in evidence:
            if not isinstance(item, str) or not (ROOT / item).resolve().exists():
                errors.append(f"missing evidence path: {item!r}")

    public_api = json.loads(PUBLIC_API.read_text(encoding="utf-8"))
    documentation = manifest.get("documentation")
    expected_documentation = {
        "example_exceptions": len(public_api["example_exceptions"]),
        "public_api_entries": len(public_api["entries"]),
        "public_modules": len(_load_tool("public_api_closure").public_modules()),
    }
    if documentation != expected_documentation:
        errors.append("documentation counts are stale")

    typing = json.loads(TYPING.read_text(encoding="utf-8"))
    expected_typing = {
        "diagnostics": typing["diagnostic_count"],
        "inline_suppressions": len(typing["inline_suppression_exceptions"]),
    }
    if manifest.get("typing") != expected_typing:
        errors.append("typing counts are stale")

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"]["optional-dependencies"]
    pinned = set(extras["dev"] + extras["docs"] + extras["quality"])
    expected_pins = {f"{name}=={version}" for name, version in EXPECTED_VERSIONS.items()}
    if not expected_pins <= pinned:
        errors.append("pyproject quality dependencies are not exactly pinned")
    if pyproject["tool"]["mypy"]["files"] != EXPECTED_SCOPE:
        errors.append("mypy scope differs from the milestone authority")
    overrides = pyproject["tool"]["mypy"].get("overrides", [])
    expected_override = {
        "module": EXPECTED_TYPING_BOUNDARIES,
        "follow_imports": "skip",
        "ignore_missing_imports": True,
    }
    if overrides != [expected_override]:
        errors.append("mypy optional-import boundary differs from the milestone authority")

    generator = _load_tool("generate_api_reference")
    if generator.DESTINATION.read_text(encoding="utf-8") != generator.render_reference():
        errors.append("generated public namespace reference is stale")

    workflow = (REPOSITORY / ".github" / "workflows" / "claasp-quality.yaml").read_text(
        encoding="utf-8"
    )
    for required in (
        'python-version: ["3.11", "3.12", "3.13"]',
        "ruff format --check src tests tools docs/conf.py",
        "ruff check src tests tools docs/conf.py",
        "python tools/typecheck_closure.py --check",
        "python tools/public_api_closure.py --check",
        "python tools/documentation_quality_closure.py --check",
        "python tools/wheel_audit.py",
    ):
        if required not in workflow:
            errors.append(f"CI quality gate is missing: {required}")

    categories = Counter(item["category"] for item in public_api["example_exceptions"])
    if categories != Counter(
        {"abstract_protocol": 8, "environment_owned_interaction": 7, "external_executable": 23}
    ):
        errors.append("reviewed example-exception categories are stale")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("pass --check")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors = validate_manifest(manifest)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    documentation = manifest["documentation"]
    typing = manifest["typing"]
    print(
        "M10.16 closure passes: "
        f"{documentation['public_api_entries']} API entries, "
        f"{documentation['example_exceptions']} example exceptions, "
        f"{typing['diagnostics']} reviewed typing diagnostics"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
