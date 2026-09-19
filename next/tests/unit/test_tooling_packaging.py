from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_runtime_tree_ships_no_legacy_native_abi_or_generated_binary():
    runtime = ROOT / "src/claasp_next"
    forbidden = {".c", ".h", ".o", ".a", ".so", ".dylib", ".dll"}
    assert not [path for path in runtime.rglob("*") if path.suffix in forbidden]


def test_package_data_remains_explicit_and_owned():
    configuration = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"*" = ["data/*.json", "data/*.dat", "data/*.md"]' in configuration
    data_files = [
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src/claasp_next").rglob("*")
        if path.is_file() and "/data/" in path.as_posix() and "__pycache__" not in path.parts
    ]
    assert data_files
    assert all(
        Path(path).suffix in {".json", ".dat", ".md"} or Path(path).name == "__init__.py"
        for path in data_files
    )
