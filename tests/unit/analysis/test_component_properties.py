from claasp.analysis import (
    ComponentProperty,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
)
from claasp.components import BitVectorSBox, LinearMap, LookupTable, SBox
from claasp.composites.aes import AES_FIELD
from claasp.domains import Bit, Word
from claasp.drivers.analysis import BoundedBranchNumberDriver
from claasp.graph import Port, ValueType
from claasp.primitives import AES, Present


def test_public_primitive_api_retains_analysis_and_realization_provenance():
    primitive = Present(number_of_rounds=1)
    sbox = next(item for item in primitive.graph.components if isinstance(item, BitVectorSBox))
    result = primitive.analysis.component_property(
        sbox,
        ComponentProperty.DIFFERENTIAL_UNIFORMITY,
        PropertyDomain.LOOKUP_TABLE,
    )

    assert result.value == 4
    assert result.claim is PropertyClaim.EXACT
    assert result.provenance.primitive == "present"
    assert result.provenance.realization == primitive.realization.name
    assert result.provenance.graph_locations
    assert sbox.component_id not in result.provenance.semantic_identity


def test_public_batch_api_keeps_each_request_and_result_typed():
    primitive = Present(number_of_rounds=1)
    sbox = next(item for item in primitive.graph.components if isinstance(item, BitVectorSBox))
    requests = (
        PropertyRequest(ComponentProperty.NONLINEARITY, PropertyDomain.LOOKUP_TABLE),
        PropertyRequest(ComponentProperty.ALGEBRAIC_DEGREE, PropertyDomain.LOOKUP_TABLE),
    )

    results = primitive.analysis.component_properties(sbox, requests)

    assert tuple(result.value for result in results) == (4, 3)
    assert tuple(result.request for result in results) == requests
    assert all(result.provenance.graph_locations for result in results)


def test_public_driver_api_keeps_realization_separate_from_driver_provenance():
    primitive = AES(number_of_rounds=1)
    linear = next(item for item in primitive.graph.components if isinstance(item, LinearMap))
    result = primitive.analysis.component_property(
        linear,
        ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
        PropertyDomain.WORD_LINEAR,
        driver=BoundedBranchNumberDriver(maximum_input_weight=1),
    )

    assert result.provenance.realization == primitive.realization.name
    assert result.provenance.driver.name == "bounded_branch_enumeration"
    assert result.provenance.graph_locations


def test_binary_and_field_linear_examples_have_fixed_evidence():
    binary = LinearMap(Port("bits", ValueType(Bit(), (2,))), ((1, 0), (1, 1)))
    mix_column = LinearMap(
        Port("column", ValueType(AES_FIELD, (4,))),
        ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)),
    )
    from claasp.analysis import analyze_component_property

    binary_result = analyze_component_property(
        binary, PropertyRequest(ComponentProperty.RANK, PropertyDomain.BIT_LINEAR)
    )
    mix_result = analyze_component_property(
        mix_column, PropertyRequest(ComponentProperty.MDS, PropertyDomain.WORD_LINEAR)
    )

    assert binary_result.value == 2
    assert mix_result.value is True


def test_unit_sbox_analysis_uses_one_unit_width_not_the_whole_vector():
    sbox = SBox(
        Port("words", ValueType(Word(2), (3,))),
        (0, 1, 3, 2),
    )
    from claasp.analysis import analyze_component_property

    result = analyze_component_property(
        sbox,
        PropertyRequest(
            ComponentProperty.ALGEBRAIC_DEGREE,
            PropertyDomain.LOOKUP_TABLE,
        ),
    )

    assert result.value == 1


def test_rectangular_lookup_anf_and_wide_values_are_supported():
    from claasp.analysis import analyze_lookup_table

    result = analyze_lookup_table(
        LookupTable((0, 511), 1, 9),
        PropertyRequest(ComponentProperty.ALGEBRAIC_DEGREE, PropertyDomain.LOOKUP_TABLE),
    )

    assert result.value == 1
