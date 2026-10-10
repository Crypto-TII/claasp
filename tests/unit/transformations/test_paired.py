import pytest

from claasp import (
    CompositeBuilder,
    PairedTransformationResult,
    PrimeField,
    Primitive,
    TransformationError,
    TransformationFailureReason,
    ValueType,
    Word,
    paired_xor_primitive,
)
from claasp.components import Identity
from claasp.graph import as_selection
from claasp.primitives import Present, Speck
from claasp.representations.constraints.sat import BooleanCNFModel

LEFT = 0x6574694C
RIGHT = 0x6574694D
KEY = 0x1918111009080100
RELATED_KEY = 0x1918111009080101


def _value(primitive, evaluation, selection):
    return primitive.graph.resolve_selection(selection, evaluation.values, {})


def _observation_value(primitive, evaluation, observation):
    selections = observation if isinstance(observation, tuple) else (observation,)
    return tuple(
        unit
        for selection in selections
        for unit in primitive.graph.resolve_selection(
            as_selection(selection), evaluation.values, {}
        )
    )


def test_single_key_pair_matches_fixed_output_and_all_published_differences():
    source = Speck(number_of_rounds=4)
    result = paired_xor_primitive(source, shared_inputs=("key",))
    paired = result.primitive
    evaluation = paired.evaluate_with_trace(LEFT, RIGHT, KEY)
    left_trace = source.evaluate_with_trace(LEFT, KEY)
    right_trace = source.evaluate_with_trace(RIGHT, KEY)

    assert isinstance(result, PairedTransformationResult)
    assert paired.evaluate(LEFT, RIGHT, KEY) == 0xFAED5B91
    assert paired.evaluate(LEFT, RIGHT, KEY) == source.evaluate(LEFT, KEY) ^ source.evaluate(
        RIGHT, KEY
    )
    assert _value(paired, evaluation, result.differences_by_input["plaintext"]) == (0, LEFT ^ RIGHT)
    assert tuple(
        _value(paired, evaluation, difference) for difference in result.round_differences
    ) == tuple(
        tuple(
            left ^ right
            for left, right in zip(
                _observation_value(source, left_trace, observation),
                _observation_value(source, right_trace, observation),
            )
        )
        for observation in source.graph.round_outputs
    )
    assert all(
        _value(paired, evaluation, difference) == (0,) for difference in result.key_differences
    )


def test_related_key_pair_has_independent_inputs_and_fixed_output_difference():
    source = Speck(number_of_rounds=4)
    result = source.edit.pair_xor()
    paired = result.primitive

    assert tuple(paired.graph.input_ports) == (
        "left_plaintext",
        "right_plaintext",
        "left_key",
        "right_key",
    )
    assert paired.evaluate(LEFT, RIGHT, KEY, RELATED_KEY) == 0xD64FCE87
    assert paired.evaluate(LEFT, RIGHT, KEY, RELATED_KEY) == (
        source.evaluate(LEFT, KEY) ^ source.evaluate(RIGHT, RELATED_KEY)
    )
    assert set(result.differences_by_input) == {"plaintext", "key"}
    assert source.transformation_provenance == ()
    assert paired.transformation_provenance[-1].operation == "paired_xor"


def test_pair_uses_composite_scopes_and_no_identity_wiring_placeholders():
    source = Present(number_of_rounds=1)
    result = paired_xor_primitive(source, shared_inputs=("key",))

    assert result.left_scope.path == "left"
    assert result.right_scope.path == "right"
    assert tuple(scope.path for scope in result.primitive.graph.scopes) == ("left", "right")
    assert not any(
        isinstance(component, Identity) for component in result.primitive.graph.components
    )
    assert result.primitive.evaluate(0, 1, 0) == source.evaluate(0, 0) ^ source.evaluate(1, 0)


def test_nested_source_scopes_remain_nested_in_each_paired_realization():
    block = CompositeBuilder("copy", {"value": ValueType(Word(4), (1,))})
    block.add_round()
    copied = block.add_component(Identity(block.input("value"), "copy"))
    block.set_output("output", copied)
    source = Primitive("scoped", {"state": ValueType(Word(4), (1,))})
    source._builder.add_round()
    instance = source._builder.add_composite(
        block.build(), {"value": source.graph.input("state")}, scope_id="block"
    )
    source._builder.set_output(instance.output())

    paired = paired_xor_primitive(source)

    assert tuple(scope.path for scope in paired.primitive.graph.scopes) == (
        "left",
        "left/block",
        "right",
        "right/block",
    )
    assert paired.primitive.evaluate(0xA, 0x3) == 0x9


def test_xor_pair_rejects_domains_without_characteristic_two_semantics():
    source = Primitive("prime", {"state": ValueType(PrimeField(7), (1,))})
    source._builder.set_output(source.graph.input("state"))

    with pytest.raises(TransformationError) as caught:
        paired_xor_primitive(source)
    assert caught.value.reason is TransformationFailureReason.UNSUPPORTED_COMPONENT


def test_paired_graph_lowers_to_an_independently_checked_sat_witness():
    paired = paired_xor_primitive(Speck(number_of_rounds=1), shared_inputs=("key",)).primitive
    evaluation = paired.evaluate_with_trace(LEFT, RIGHT, KEY)
    model = BooleanCNFModel(paired)

    assert model.cnf_formula().is_satisfied(model.witness(evaluation))
