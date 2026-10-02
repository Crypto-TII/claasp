"""Enforce package ownership for the unit-test tree."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPOSITORY_ROOT / "src" / "claasp"
UNIT_ROOT = REPOSITORY_ROOT / "tests" / "unit"
ROOT_API_TESTS = {
    "test_authoring_api.py": "__init__.py",
}


def test_unit_tests_mirror_their_source_package_owner():
    """Every functional test directory must identify an existing source package."""
    misplaced = []
    for test_path in sorted(UNIT_ROOT.rglob("test_*.py")):
        relative_path = test_path.relative_to(UNIT_ROOT)
        if relative_path.parts[0] == "repository":
            continue
        if len(relative_path.parts) == 1:
            source_name = ROOT_API_TESTS.get(test_path.name, test_path.name.removeprefix("test_"))
            source_owner = SOURCE_ROOT / source_name
        else:
            source_owner = SOURCE_ROOT.joinpath(*relative_path.parts[:-1])
        if not source_owner.exists():
            misplaced.append(f"{relative_path} -> {source_owner.relative_to(REPOSITORY_ROOT)}")

    assert misplaced == []


def test_root_unit_tests_are_source_modules_or_registered_api_facades():
    """Root-level tests may cover only root modules or an explicit package facade."""
    unexpected = []
    for test_path in sorted(UNIT_ROOT.glob("test_*.py")):
        source_name = ROOT_API_TESTS.get(test_path.name, test_path.name.removeprefix("test_"))
        if not (SOURCE_ROOT / source_name).is_file():
            unexpected.append(test_path.name)

    assert unexpected == []
