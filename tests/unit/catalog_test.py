import ast
from pathlib import Path
from types import SimpleNamespace

import claasp.catalog as catalog_module
from claasp.catalog import Catalog, CipherInfo


def test_ciphers_filter_by_required_components_and_aliases():
    table = Catalog().ciphers(filters=["toy"], has_components=["sbox", "xor"])

    assert table["rows"]
    assert all("toys" in row["tags"] for row in table["rows"])
    assert all({"sbox", "xor"}.issubset(set(row["components"])) for row in table["rows"])
    assert any(row["class_name"] == "FancyBlockCipher" for row in table["rows"])


def test_ciphers_include_metadata_success_path():
    table = Catalog().ciphers(filters="stream_ciphers", include_metadata=True)
    row = next(row for row in table["rows"] if row["class_name"] == "A51StreamCipher")

    assert "qualified_name" not in row
    assert row["cipher_type"] == "stream_cipher"
    assert row["family_name"] == "a51"
    assert row["metadata_error"] is None


def test_ciphers_include_metadata_error_path(monkeypatch):
    catalog = Catalog()
    broken_info = next(info for info in catalog._cipher_infos if info.name == "SpeckBlockCipher")

    def fake_load_cipher_instance(qualified_name):
        raise RuntimeError(f"boom: {qualified_name}")

    monkeypatch.setattr("claasp.catalog._load_cipher_instance", fake_load_cipher_instance)

    table = catalog.ciphers(filters="block_ciphers", include_metadata=True, qualified=True)
    row = next(row for row in table["rows"] if row["class_name"] == broken_info.name)

    assert row["qualified_name"] == broken_info.qualified_name
    assert row["family_name"] is None
    assert row["metadata_error"].startswith("RuntimeError: boom:")


def test_ciphers_returns_empty_rows_for_unmatched_component_filter():
    table = Catalog().ciphers(filters="mac", has_components=["sbox"])

    assert table["rows"] == []


def test_ciphers_contains_known_classes_table():
    table = Catalog().ciphers()
    names = {row["class_name"] for row in table["rows"]}

    assert table["name"] == "ciphers"
    assert "class_name" in table["columns"]
    assert "SpeckBlockCipher" in names
    assert "ChachaPermutation" in names


def test_ciphers_filter_and_qualified_mode():
    table = Catalog().ciphers(filters="block_ciphers", qualified=True)

    assert table["rows"]
    assert all("block_ciphers" in row["tags"] for row in table["rows"])
    assert any(row["qualified_name"].endswith(".SpeckBlockCipher") for row in table["rows"])


def test_components_default_excludes_abstract_and_io():
    table = Catalog().components()
    names = {row["class_name"] for row in table["rows"]}

    assert "And" in names
    assert "MultiInputNonlinearLogicalOperator" not in names
    assert "Modular" not in names
    assert "CipherOutput" not in names
    assert "IntermediateOutput" not in names


def test_components_can_include_abstract_and_io():
    table = Catalog().components(include_abstract=True, include_io_components=True)
    names = {row["class_name"] for row in table["rows"]}

    assert "MultiInputNonlinearLogicalOperator" in names
    assert "Modular" in names
    assert "CipherOutput" in names
    assert "IntermediateOutput" in names


def test_implemented_methods_per_component_shape_and_content():
    table = Catalog().implemented_methods_per_component(include_abstract=False)

    assert table["columns"][0] == "method"
    assert "And" in table["columns"]
    assert "Modular" not in table["columns"]
    assert any(row["method"] == "sat_constraints" for row in table["rows"])


def test_solvers_contains_known_entries_and_availability():
    grouped = Catalog().solvers(grouped=True)

    assert any(row["solver_name"] == "chuffed" for row in grouped["cp"]["rows"])
    assert any(row["solver_name"] == "CRYPTOMINISAT_EXT" for row in grouped["sat"]["rows"])
    assert any(row["solver_name"] == "Z3_EXT" for row in grouped["smt"]["rows"])
    assert any(row["solver_name"] == "GLPK" for row in grouped["milp"]["rows"])
    assert all("available" in row for family in grouped.values() for row in family["rows"])


def test_table_render_and_write(tmp_path):
    catalog = Catalog()
    table = catalog.components()

    markdown = catalog.to_markdown(table)
    csv_text = catalog.to_csv(table)
    json_text = catalog.to_json(table)

    assert markdown.startswith("| ")
    assert "class_name" in csv_text
    assert json_text.startswith("{")

    output = tmp_path / "components.csv"
    written = catalog.write(table, output, fmt="csv")
    assert written == output
    assert output.read_text(encoding="utf-8").startswith("class_name")


def test_catalog_import_resolution_helpers_cover_relative_and_absolute_paths():
    source = """
import claasp.ciphers.block_ciphers.speck_block_cipher
from claasp.ciphers.stream_ciphers import a5_1_stream_cipher
from ..ciphers.toys import fancy_block_cipher
from . import local_module
from external.module import something
"""
    tree = ast.parse(source)

    modules = catalog_module._imported_cipher_modules(tree, "claasp.tests.unit.catalog_test")

    assert "claasp.ciphers.block_ciphers.speck_block_cipher" in modules
    assert "claasp.ciphers.stream_ciphers" in modules
    assert "claasp.ciphers.toys" in modules
    assert "external.module" not in modules


def test_catalog_source_file_and_category_helpers():
    assert catalog_module._is_python_source_file(Path("alpha.py"))
    assert not catalog_module._is_python_source_file(Path("__init__.py"))
    assert not catalog_module._is_python_source_file(Path("_private.py"))

    ciphers_dir = Path("/tmp/root/ciphers")
    file_path = ciphers_dir / "block_ciphers" / "demo.py"
    assert catalog_module._cipher_category_from_path(file_path, ciphers_dir) == "block_ciphers"


def test_catalog_discover_cipher_infos_from_file(tmp_path):
    package_root = tmp_path / "claasp"
    ciphers_dir = package_root / "ciphers"
    module_dir = ciphers_dir / "toys"
    module_dir.mkdir(parents=True)
    file_path = module_dir / "toy_cipher.py"
    file_path.write_text(
        "class TinyCipher(Cipher):\n"
        "    def __init__(self):\n"
        "        self.add_xor_component(None, None, None)\n",
        encoding="utf-8",
    )

    infos = catalog_module._discover_cipher_infos_from_file(file_path, ciphers_dir, package_root, {})

    assert len(infos) == 1
    assert infos[0].name == "TinyCipher"
    assert infos[0].category == "toys"
    assert "xor" in infos[0].components


def test_catalog_collect_imported_components_and_filters(monkeypatch):
    tree = ast.parse("pass")

    monkeypatch.setattr(catalog_module, "_imported_cipher_modules", lambda _tree, _module: {"claasp.ciphers.mock"})
    monkeypatch.setattr(
        catalog_module,
        "_collect_components_from_cipher_module",
        lambda _module, _root, _cache, _visiting: {"xor", "rotate"},
    )

    components = catalog_module._collect_imported_components(tree, "claasp.any", Path("/tmp"), {})
    assert components == {"xor", "rotate"}

    info = CipherInfo(
        name="X",
        qualified_name="claasp.ciphers.toys.x.X",
        module_name="claasp.ciphers.toys.x",
        category="toys",
        paradigm="other",
        components=("xor", "sbox"),
        tags=frozenset({"toys", "sbox_based"}),
    )
    assert catalog_module._matches_cipher_filters(info, {"toys"}, {"xor"})
    assert not catalog_module._matches_cipher_filters(info, {"mac"}, {"xor"})
    assert not catalog_module._matches_cipher_filters(info, {"toys"}, {"modadd"})


def test_catalog_cipher_metadata_and_row_helpers(monkeypatch):
    fake_instance = SimpleNamespace(
        family_name="demo",
        type="block_cipher",
        inputs=["plaintext"],
        inputs_bit_size=[64],
        output_bit_size=64,
        number_of_rounds=4,
        id="demo_p64_o64_r4",
    )
    monkeypatch.setattr(catalog_module, "_load_cipher_instance", lambda _qname: fake_instance)

    metadata = catalog_module._cipher_metadata("claasp.ciphers.toys.demo.DemoCipher")
    assert metadata["family_name"] == "demo"
    assert metadata["metadata_error"] is None

    info = CipherInfo(
        name="DemoCipher",
        qualified_name="claasp.ciphers.toys.demo.DemoCipher",
        module_name="claasp.ciphers.toys.demo",
        category="toys",
        paradigm="other",
        components=("xor",),
        tags=frozenset({"toys"}),
    )
    row = catalog_module._cipher_row(info, include_metadata=True, qualified=False)
    assert row["class_name"] == "DemoCipher"
    assert "qualified_name" not in row
    assert row["family_name"] == "demo"

    monkeypatch.setattr(catalog_module, "_load_cipher_instance", lambda _qname: (_ for _ in ()).throw(RuntimeError("boom")))
    error_metadata = catalog_module._cipher_metadata("claasp.ciphers.toys.demo.DemoCipher")
    assert error_metadata["metadata_error"].startswith("RuntimeError: boom")
