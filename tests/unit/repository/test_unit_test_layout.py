"""Enforce package ownership for the unit-test tree."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPOSITORY_ROOT / "src" / "claasp"
UNIT_ROOT = REPOSITORY_ROOT / "tests" / "unit"


def _source_owner(test_path: Path) -> Path:
    """Return the source module encoded by one unit-test path."""

    relative_path = test_path.relative_to(UNIT_ROOT)
    test_stem = test_path.stem.removeprefix("test_")
    owner_stem = test_stem.partition("__")[0]
    source_name = "__init__.py" if owner_stem == "package" else f"{owner_stem}.py"
    return SOURCE_ROOT.joinpath(*relative_path.parts[:-1], source_name)


def test_unit_tests_mirror_their_source_module_owner():
    """Every functional unit test must encode an existing source module."""
    misplaced = []
    for test_path in sorted(UNIT_ROOT.rglob("test_*.py")):
        relative_path = test_path.relative_to(UNIT_ROOT)
        if relative_path.parts[0] == "repository":
            continue
        source_owner = _source_owner(test_path)
        if not source_owner.is_file():
            misplaced.append(f"{relative_path} -> {source_owner.relative_to(REPOSITORY_ROOT)}")

    assert misplaced == []


def test_focused_suite_suffixes_are_nonempty():
    """A focused-suite separator must be followed by a descriptive topic."""

    malformed = [
        str(path.relative_to(UNIT_ROOT))
        for path in sorted(UNIT_ROOT.rglob("test_*__.py"))
        if path.relative_to(UNIT_ROOT).parts[0] != "repository"
    ]
    assert malformed == []
