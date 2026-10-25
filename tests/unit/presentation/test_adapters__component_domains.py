"""Component reports describe mathematical spaces rather than analyzer tags."""

from io import StringIO

from claasp import PrimitiveBuilder, UnitArrayType
from claasp.components import LinearMap
from claasp.composites import AESMixColumn, AESSubstitutionLayer
from claasp.presentation import component_property_section, present
from claasp.primitives import DES, Present, ToyAES
from claasp.unit_types import PrimeField


def _domain(result, *, details=False):
    output = StringIO()
    result.to_terminal(details=details, file=output)
    return output.getvalue()


def test_sbox_report_names_binary_input_and_output_spaces_without_changing_requests():
    sbox = Present(number_of_rounds=1).analysis.component("sbox")
    properties = sbox.properties("nonlinearity")
    text = _domain(properties)
    assert "4-bit vectors → 4-bit vectors; bit weights" in text
    assert "lookup_table" not in text
    assert properties[0].request.domain.value == "lookup_table"
    columns = present(properties).sections[0].tables[0].columns
    assert columns[1].key == "domain" and columns[1].heading == "Domain"


def test_rectangular_des_domain_does_not_imply_bijectivity_from_balance():
    properties = DES().analysis.component("sbox", index=0).properties("balanced", "invertible")
    assert [result.value for result in properties] == [True, False]
    assert "6-bit vectors → 4-bit vectors" in _domain(properties)


def test_field_report_names_field_dimension_weights_and_detailed_modulus():
    linear = AESMixColumn().analyze().component("linear_map")
    properties = linear.properties("rank")
    assert "GF(2^8)^4 → GF(2^8)^4; byte weights" in _domain(properties)
    assert "modulus=0x11b" in _domain(properties, details=True)
    binary = linear.properties("rank", domain="bit_linear")
    assert binary[0].value == 32
    assert "32-bit vectors → 32-bit vectors; bit weights" in _domain(binary)


def test_parallel_substitution_uses_scalar_lookup_dimensions():
    sbox = ToyAES(word_size=3, state_size=3, number_of_rounds=2).analysis.component(
        "sbox", bit_size=27
    )
    text = _domain(sbox.properties("nonlinearity"))
    assert "3-bit vectors → 3-bit vectors; bit weights (per lookup)" in text
    assert "27-bit vectors" not in text


def test_prime_field_report_does_not_treat_encoded_elements_as_bytes():
    builder = PrimitiveBuilder("prime_map", {"data": UnitArrayType(PrimeField(251), (2,))})
    builder.add_round()
    output = builder.add_component(LinearMap(builder.input("data"), ((1, 0), (0, 1))))
    properties = builder.build(output).analysis.component("linear_map").properties("rank")
    assert "GF(251)^2 → GF(251)^2; element weights" in _domain(properties)
    assert "byte weights" not in _domain(properties)


def test_raw_property_adapter_does_not_invent_dimensions_without_source_semantics():
    properties = AESMixColumn().analyze().component("linear_map").properties("rank")
    table = component_property_section(properties.results, details=False).tables[0]
    assert table.rows[0].cells[1].text == "Finite-field vectors; element weights"


def test_parallel_binary_affine_map_reports_the_analyzed_per_unit_matrix():
    affine = (
        AESSubstitutionLayer(16, realization="algebraic").analyze().component("binary_affine_map")
    )
    properties = affine.properties("rank")
    assert properties[0].value == 8
    text = _domain(properties)
    assert "8-bit vectors → 8-bit vectors; bit weights (per unit)" in text
    assert "128-bit vectors" not in text
