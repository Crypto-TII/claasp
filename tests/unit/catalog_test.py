from claasp.catalog import Catalog


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
