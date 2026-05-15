import ast
import builtins
from pathlib import Path
from types import SimpleNamespace

import claasp.catalog as catalog_module
import pytest
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


def test_ciphers_filter_arx_includes_known_arx_block_ciphers():
    table = Catalog().ciphers(filters="arx")
    names = {row["class_name"] for row in table["rows"]}

    assert "SpeckBlockCipher" in names
    assert "ChachaPermutation" in names
    assert "ZucStreamCipher" not in names
    arx_set = {"constant", "modadd", "rotate", "xor"}
    pure_arx_set = {"modadd", "rotate", "xor"}
    assert all(set(row["components"]) in (arx_set, pure_arx_set) for row in table["rows"])


def test_ciphers_filter_purearx_reports_only_exact_modadd_rotate_xor_ciphers():
    table = Catalog().ciphers(filters="purearx")
    names = {row["class_name"] for row in table["rows"]}

    assert "ChachaPermutation" in names
    assert "SpeckBlockCipher" not in names
    assert all(set(row["components"]) == {"modadd", "rotate", "xor"} for row in table["rows"])


def test_ciphers_filter_andrx_includes_pureandrx_and_excludes_mixed_designs():
    table = Catalog().ciphers(filters="andrx")
    names = {row["class_name"] for row in table["rows"]}

    assert "SimonBlockCipher" in names
    assert "SimeckBlockCipher" in names
    assert "AradiBlockCipher" in names
    assert "AsconPermutation" not in names
    andrx_set = {"and", "constant", "rotate", "xor"}
    pure_andrx_set = {"and", "rotate", "xor"}
    assert all(set(row["components"]) in (andrx_set, pure_andrx_set) for row in table["rows"])


def test_ciphers_filter_pureandrx_reports_only_exact_and_rotate_xor_ciphers():
    table = Catalog().ciphers(filters="pureandrx")
    names = {row["class_name"] for row in table["rows"]}

    assert "SimonBlockCipher" not in names
    assert all(set(row["components"]) == {"and", "rotate", "xor"} for row in table["rows"])


def test_ciphers_filter_fsr_based_reports_only_fsr_ciphers():
    table = Catalog().ciphers(filters="fsr_based")
    names = {row["class_name"] for row in table["rows"]}

    assert "A51StreamCipher" in names
    assert "A52StreamCipher" in names
    assert "AESBlockCipher" not in names
    assert all("fsr" in set(row["components"]) for row in table["rows"])


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

    modules = catalog_module._imported_cipher_modules(tree, "claasp.tests.unit.catalog_test", Path("/nonexistent"))

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

    infos = catalog_module._discover_cipher_infos_from_file(
        file_path,
        ciphers_dir,
        package_root,
        {},
        {"xor"},
    )

    assert len(infos) == 1
    assert infos[0].name == "TinyCipher"
    assert infos[0].category == "toys"
    assert "xor" in infos[0].components


def test_catalog_collect_imported_components_and_filters(monkeypatch):
    tree = ast.parse("pass")

    monkeypatch.setattr(catalog_module, "_imported_cipher_modules", lambda _tree, _module, _root: {"claasp.ciphers.mock"})
    monkeypatch.setattr(
        catalog_module,
        "_collect_components_from_cipher_module",
        lambda _module, _root, _cache, _visiting, _allowed: {"xor", "rotate"},
    )

    components = catalog_module._collect_imported_components(tree, "claasp.any", Path("/tmp"), {}, {"xor", "rotate"})
    assert components == {"xor", "rotate"}

    info = CipherInfo(
        name="X",
        qualified_name="claasp.ciphers.toys.x.X",
        module_name="claasp.ciphers.toys.x",
        category="toys",
        components=("xor", "sbox"),
        tags=frozenset({"toys", "sbox_based"}),
    )
    assert catalog_module._matches_cipher_filters(info, {"toys"}, {"xor"})
    assert not catalog_module._matches_cipher_filters(info, {"mac"}, {"xor"})
    assert not catalog_module._matches_cipher_filters(info, {"toys"}, {"modadd"})

    pure_arx_info = CipherInfo(
        name="PureArx",
        qualified_name="claasp.ciphers.toys.pure.PureArx",
        module_name="claasp.ciphers.toys.pure",
        category="toys",
        components=("modadd", "rotate", "xor"),
        tags=frozenset({"toys", "purearx", "arx"}),
    )
    arx_info = CipherInfo(
        name="Arx",
        qualified_name="claasp.ciphers.toys.arx.Arx",
        module_name="claasp.ciphers.toys.arx",
        category="toys",
        components=("constant", "modadd", "rotate", "xor"),
        tags=frozenset({"toys", "arx"}),
    )
    mixed_info = CipherInfo(
        name="Mixed",
        qualified_name="claasp.ciphers.toys.mixed.Mixed",
        module_name="claasp.ciphers.toys.mixed",
        category="toys",
        components=("modadd", "rotate", "sbox", "xor"),
        tags=frozenset({"toys", "sbox_based"}),
    )
    pure_andrx_info = CipherInfo(
        name="PureAndrx",
        qualified_name="claasp.ciphers.toys.pure.PureAndrx",
        module_name="claasp.ciphers.toys.pure",
        category="toys",
        components=("and", "rotate", "xor"),
        tags=frozenset({"toys", "pureandrx", "andrx"}),
    )
    andrx_info = CipherInfo(
        name="Andrx",
        qualified_name="claasp.ciphers.toys.andrx.Andrx",
        module_name="claasp.ciphers.toys.andrx",
        category="toys",
        components=("and", "constant", "rotate", "xor"),
        tags=frozenset({"toys", "andrx"}),
    )
    mixed_andrx_info = CipherInfo(
        name="MixedAndrx",
        qualified_name="claasp.ciphers.toys.mixed.MixedAndrx",
        module_name="claasp.ciphers.toys.mixed",
        category="toys",
        components=("and", "constant", "not", "rotate", "xor"),
        tags=frozenset({"toys"}),
    )

    assert catalog_module._matches_cipher_filters(pure_arx_info, {"purearx"}, set())
    assert catalog_module._matches_cipher_filters(pure_arx_info, {"arx"}, set())  # purearx ⊆ arx
    assert catalog_module._matches_cipher_filters(arx_info, {"arx"}, set())
    assert not catalog_module._matches_cipher_filters(arx_info, {"purearx"}, set())
    assert not catalog_module._matches_cipher_filters(mixed_info, {"arx"}, set())
    assert catalog_module._matches_cipher_filters(pure_andrx_info, {"pureandrx"}, set())
    assert catalog_module._matches_cipher_filters(pure_andrx_info, {"andrx"}, set())  # pureandrx ⊆ andrx
    assert catalog_module._matches_cipher_filters(andrx_info, {"andrx"}, set())
    assert not catalog_module._matches_cipher_filters(andrx_info, {"pureandrx"}, set())
    assert not catalog_module._matches_cipher_filters(mixed_andrx_info, {"andrx"}, set())


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


def test_catalog_helper_normalization_and_projection_branches():
    assert catalog_module._normalize_column_selector(None) is None
    assert catalog_module._normalize_column_selector([" class_name ", "", "class_name", "tags"]) == [
        "class_name",
        "tags",
    ]

    table = {
        "name": "demo",
        "columns": ["class_name", "module_name", "tags"],
        "rows": [{"class_name": "Demo", "module_name": "demo.module", "tags": ["toys"]}],
    }

    projected = catalog_module._project_table_columns(table, columns=["tags", "class_name"])
    assert projected["columns"] == ["class_name", "tags"]
    assert projected["rows"] == [{"class_name": "Demo", "tags": ["toys"]}]

    projected = catalog_module._project_table_columns(table, exclude_columns="module_name")
    assert projected["columns"] == ["class_name", "tags"]

    with pytest.raises(ValueError, match="Unknown selected columns"):
        catalog_module._project_table_columns(table, columns=["missing"])

    with pytest.raises(ValueError, match="Unknown excluded columns"):
        catalog_module._project_table_columns(table, exclude_columns=["missing"])


def test_catalog_filter_component_and_solver_helpers(monkeypatch):
    allowed = {"block_ciphers", "toys", "sbox_based", "fsr_based"}

    assert catalog_module._normalize_filters(["Toy", "sbox-based"], allowed) == {"toys", "sbox_based"}
    assert catalog_module._normalize_filters(["fsr-based"], allowed) == {"fsr_based"}
    assert catalog_module._normalize_components_filter([" variable-rotate ", "xor", ""]) == {"rotate", "xor"}
    assert catalog_module._supported_cipher_filters({"toys"}) >= {
        "toys",
        "arx",
        "purearx",
        "andrx",
        "pureandrx",
        "sbox_based",
        "fsr_based",
    }

    with pytest.raises(ValueError, match="Unknown cipher filters"):
        catalog_module._normalize_filters(["unknown-filter"], allowed)

    monkeypatch.setattr(catalog_module.shutil, "which", lambda executable: "/usr/bin/fake" if executable == "solver" else None)
    assert catalog_module._extract_external_solver_executable({"keywords": {"command": {"executable": "solver"}}}) == "solver"
    assert catalog_module._extract_external_solver_executable(
        {"keywords": {"command": {"executable": ["-s", "", "solver-list"]}}}
    ) == "solver-list"
    assert catalog_module._extract_external_solver_executable({"keywords": {"command": {"executable": ["-a", ""]}}}) is None
    assert not catalog_module._solver_is_available(None)
    assert catalog_module._solver_is_available("solver")

    rows = catalog_module._collect_solver_entries(
        "sat",
        [{"solver_name": "INTERNAL", "solver_brand_name": "internal"}],
        [{"solver_name": "EXTERNAL", "solver_brand_name": "external", "keywords": {"command": {"executable": "solver"}}}],
        include_internal=True,
        include_external=True,
    )
    assert [row["source"] for row in rows] == ["external", "internal"]
    assert rows[0]["available"] is True


def test_catalog_ast_and_path_helpers(tmp_path):
    package_root = tmp_path / "claasp"
    package_root.mkdir()
    source_file = package_root / "demo_module.py"
    source_file.write_text(
        "class DemoCipher(Cipher):\n"
        "    def public(self):\n"
        "        return 1\n"
        "    def _private(self):\n"
        "        return 0\n",
        encoding="utf-8",
    )

    classes = catalog_module._iter_classes_in_tree(source_file)
    assert [class_node.name for class_node in classes] == ["DemoCipher"]
    assert catalog_module._public_methods_from_class(classes[0]) == {"public"}
    assert catalog_module._module_path_from_file(source_file, package_root) == "claasp.demo_module"

    attr_node = ast.parse("pkg.Cipher").body[0].value
    const_node = ast.parse("1").body[0].value
    assert catalog_module._base_name(attr_node) == "Cipher"
    assert catalog_module._base_name(const_node) is None

    hidden_class = ast.parse("class _Hidden(Cipher):\n    pass\n").body[0]
    no_base_class = ast.parse("class Plain:\n    pass\n").body[0]
    permutation_class = ast.parse("class DemoPermutation(BasePermutation):\n    pass\n").body[0]
    assert not catalog_module._is_cipher_class(hidden_class)
    assert not catalog_module._is_cipher_class(no_base_class)
    assert catalog_module._is_cipher_class(permutation_class)

    components = catalog_module._cipher_components(
        "self.add_output_component()\n"
        "self.add_variable_rotate_component()\n"
        "self.add_round_output_component()\n"
        "self.add_crazy_component()\n"
        "self.add_xor_component()\n"
    )
    assert components == {"rotate", "xor"}


def test_allowed_cipher_component_names_includes_component_modules(tmp_path):
    package_root = tmp_path / "claasp"
    package_root.mkdir()

    (package_root / "cipher.py").write_text("class Cipher:\n    pass\n", encoding="utf-8")
    components_dir = package_root / "components"
    components_dir.mkdir()
    (components_dir / "crazy_component.py").write_text("class Crazy:\n    pass\n", encoding="utf-8")
    (components_dir / "cipher_output_component.py").write_text("class CipherOutput:\n    pass\n", encoding="utf-8")

    allowed = catalog_module._allowed_cipher_component_names(package_root)
    assert "crazy" in allowed
    assert "cipher_output" not in allowed


def test_catalog_module_resolution_and_import_helpers(tmp_path):
    package_root = tmp_path / "claasp"
    module_dir = package_root / "ciphers" / "toys"
    package_dir = package_root / "ciphers" / "single_component_ciphers"
    module_dir.mkdir(parents=True)
    package_dir.mkdir(parents=True)
    (module_dir / "demo.py").write_text("pass\n", encoding="utf-8")
    (package_dir / "__init__.py").write_text("pass\n", encoding="utf-8")

    assert catalog_module._resolve_module_source_file("external.module", package_root) is None
    assert catalog_module._resolve_module_source_file("claasp.ciphers.toys.demo", package_root) == module_dir / "demo.py"
    assert catalog_module._resolve_module_source_file("claasp.ciphers.single_component_ciphers", package_root) == package_dir / "__init__.py"

    absolute_from = ast.parse("from claasp.ciphers.toys import demo\n").body[0]
    relative_from = ast.parse("from ..ciphers.toys import demo\n").body[0]
    base_only_from = ast.parse("from .. import demo\n").body[0]
    too_deep_from = ast.ImportFrom(module="demo", names=[ast.alias(name="x")], level=5)

    assert catalog_module._resolve_imported_module_name(absolute_from, ["claasp", "tests", "unit"]) == "claasp.ciphers.toys"
    assert catalog_module._resolve_imported_module_name(relative_from, ["claasp", "tests", "unit", "catalog_test"]) == "claasp.ciphers.toys"
    assert catalog_module._resolve_imported_module_name(base_only_from, ["claasp", "ciphers", "toys", "demo"]) == "claasp.ciphers"
    assert catalog_module._resolve_imported_module_name(too_deep_from, ["claasp", "tests", "unit"]) is None

    tree = ast.parse("import claasp.ciphers.toys.demo\nfrom ..ciphers.toys import demo\n")
    assert catalog_module._imported_cipher_modules(tree, "claasp.tests.unit.catalog_test", package_root) == {
        "claasp.ciphers.toys.demo",
    }


def test_catalog_collect_components_from_module_branches_and_tags(tmp_path):
    package_root = tmp_path / "claasp"
    toys_dir = package_root / "ciphers" / "toys"
    toys_dir.mkdir(parents=True)
    (toys_dir / "child.py").write_text("self.add_xor_component()\n", encoding="utf-8")
    (toys_dir / "parent.py").write_text(
        "import claasp.ciphers.toys.child\n"
        "self.add_sbox_component()\n",
        encoding="utf-8",
    )

    cache = {"claasp.ciphers.toys.cached": {"rotate"}}
    assert catalog_module._collect_components_from_cipher_module(
        "claasp.ciphers.toys.cached", package_root, cache, set(), {"rotate"}
    ) == {"rotate"}
    assert catalog_module._collect_components_from_cipher_module(
        "claasp.ciphers.toys.parent", package_root, {}, set(), {"sbox", "xor"}
    ) == {"sbox", "xor"}
    assert catalog_module._collect_components_from_cipher_module(
        "claasp.ciphers.toys.parent", package_root, {}, {"claasp.ciphers.toys.parent"}, {"sbox", "xor"}
    ) == set()
    assert catalog_module._collect_components_from_cipher_module(
        "claasp.ciphers.toys.missing", package_root, {}, set(), {"sbox", "xor"}
    ) == set()

    assert catalog_module._infer_cipher_design_tags({"and", "rotate", "xor"}) == {"pureandrx", "andrx"}
    assert catalog_module._infer_cipher_design_tags({"modadd", "rotate", "xor"}) == {"purearx", "arx"}
    assert catalog_module._infer_cipher_design_tags({"constant", "modadd", "rotate", "xor"}) == {"arx"}
    assert catalog_module._infer_cipher_design_tags({"constant", "modadd", "rotate", "sbox", "xor"}) == {"sbox_based"}
    assert catalog_module._infer_cipher_design_tags({"constant", "fsr", "xor"}) == {"fsr_based"}
    assert catalog_module._infer_cipher_design_tags({"and", "constant", "rotate", "xor"}) == {"andrx"}
    assert catalog_module._infer_cipher_design_tags({"and", "constant", "rotate", "sbox", "xor"}) == {"sbox_based"}
    assert catalog_module._infer_cipher_design_tags({"sbox", "xor"}) == {"sbox_based"}
    assert catalog_module._cipher_tags("hash_functions", "uses tweak", "MantisHash", {"constant", "rotate", "sbox", "xor"}) >= {
        "hash_function",
        "sbox_based",
        "tweakable_block_cipher",
    }


def test_catalog_dataframe_render_write_and_show_helpers(monkeypatch, tmp_path):
    table = {"name": "demo", "columns": ["k", "v"], "rows": [{"k": "alpha", "v": 1}]}
    catalog = Catalog()

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pandas":
            raise ImportError("missing pandas")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match="pandas is required"):
        catalog.to_dataframe(table)
    monkeypatch.setattr(builtins, "__import__", original_import)

    assert catalog.to_terminal({"name": "empty", "columns": [], "rows": []}) == ""
    assert catalog.render(table, fmt="json").startswith("{")
    assert catalog.render(table, fmt="terminal").splitlines()[0] == "k     | v"

    with pytest.raises(ValueError, match="Unknown output format"):
        catalog.render(table, fmt="yaml")

    terminal_path = tmp_path / "table.txt"
    assert catalog.write(table, terminal_path, fmt="terminal").read_text(encoding="utf-8").startswith("k")

    show_components = catalog.show_components(qualified=True, columns=["class_name", "qualified_name"], fmt="markdown")
    show_ciphers = catalog.show_ciphers(filters="toys", columns=["class_name"], fmt="json")
    show_solvers = catalog.show_solvers(include_external=False, columns=["solver_name", "family"], fmt="terminal")
    show_methods = catalog.show_implemented_methods_per_component(columns=["method", "And"], fmt="csv")

    assert isinstance(show_components, catalog_module.RenderedText)
    assert repr(show_components) == str(show_components)
    assert "qualified_name" in show_components
    assert '"class_name"' in show_ciphers
    assert show_solvers.splitlines()[0].startswith("solver_name")
    assert show_solvers.splitlines()[0].endswith("| family")
    assert show_methods.splitlines()[0] == "method,And"


def test_catalog_solvers_flat_and_empty_modes():
    catalog = Catalog()

    external_only = catalog.solvers(include_internal=False)
    assert external_only["name"] == "solvers"
    assert external_only["rows"]
    assert all(row["source"] == "external" for row in external_only["rows"])

    none_enabled = catalog.solvers(include_internal=False, include_external=False)
    assert none_enabled["rows"] == []
