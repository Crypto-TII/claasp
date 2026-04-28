from claasp.catalog import (
    build_component_method_table,
    list_claasp_ciphers,
    list_component_classes,
    list_real_component_classes,
    render_component_method_table_markdown,
)


def test_list_claasp_ciphers_contains_known_classes():
    ciphers = list_claasp_ciphers()

    assert "SpeckBlockCipher" in ciphers
    assert "ChachaPermutation" in ciphers


def test_list_claasp_ciphers_qualified_mode():
    ciphers = list_claasp_ciphers(qualified=True)

    assert any(name.endswith(".SpeckBlockCipher") for name in ciphers)


def test_list_component_classes_and_real_components():
    components = list_component_classes()
    real_components = list_real_component_classes()

    assert "And" in components
    assert "MultiInputNonlinearLogicalOperator" in components
    assert "Modular" in components
    assert "MultiInputNonlinearLogicalOperator" not in real_components
    assert "Modular" not in real_components
    assert "And" in real_components


def test_build_component_method_table_shape_and_content():
    header, rows = build_component_method_table(include_abstract=False)

    assert header[0] == "method"
    assert "And" in header
    assert "Modular" not in header
    assert any(row[0] == "sat_constraints" for row in rows)


def test_render_component_method_table_markdown_header():
    text = render_component_method_table_markdown(include_abstract=False)

    assert text.startswith("Legend: X=implemented in class, B=inherited from Component")
    assert "| method |" in text
