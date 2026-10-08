from claasp import (
    Bit,
    CompositeBuilder,
    DependencyIndex,
    Primitive,
    TransformationError,
    TransformationFailureReason,
    ValueType,
    reduce_rounds,
    slice_primitive,
    slice_rounds,
)
from claasp.components import Identity
from claasp.graph import as_selection
from claasp.primitives import Speck

PLAINTEXT = 0x6574694C
KEY = 0x1918111009080100


def _selected_value(primitive, result, values):
    cache = {}
    selections = result if isinstance(result, tuple) else (result,)
    return tuple(
        unit
        for selection in selections
        for unit in primitive.graph.resolve_selection(as_selection(selection), values, cache)
    )


def test_dependency_slice_matches_independent_round_state_evaluation():
    primitive = Speck(number_of_rounds=3)
    trace = primitive.evaluate_with_trace(PLAINTEXT, KEY)
    expected = _selected_value(primitive, primitive.graph.round_states[1], trace.values)

    result = slice_primitive(primitive, primitive.graph.round_states[1])
    derived = result.primitive

    assert (
        derived._decode_boundary(derived.evaluate(PLAINTEXT, KEY), derived.graph.output.value_type)
        == expected
    )
    assert len(derived.graph.components) < len(primitive.graph.components)
    assert len(primitive.graph.rounds) == 3
    assert derived.transformation_provenance[-1].operation == "slice"
    DependencyIndex(derived)


def test_middle_round_slice_retains_key_schedule_and_accepts_state_boundary():
    primitive = Speck(number_of_rounds=3)
    trace = primitive.evaluate_with_trace(PLAINTEXT, KEY)
    start = _selected_value(primitive, primitive.graph.round_states[0], trace.values)
    expected = _selected_value(primitive, primitive.graph.round_states[2], trace.values)

    derived = slice_rounds(primitive, 1, 2).primitive
    actual = derived._decode_boundary(
        derived.evaluate(state=start, key=KEY),
        derived.graph.output.value_type,
    )

    assert actual == expected
    assert tuple(derived.graph.input_ports) == ("state", "key")
    assert derived.realization == primitive.realization


def test_round_reduction_is_a_validated_prefix_and_does_not_mutate_source():
    primitive = Speck(number_of_rounds=3)
    reduced = reduce_rounds(primitive, 2).primitive

    assert reduced.evaluate(PLAINTEXT, KEY) == slice_rounds(primitive, 0, 1).primitive.evaluate(
        PLAINTEXT, KEY
    )
    assert len(reduced.graph.rounds) <= 2
    assert len(primitive.graph.rounds) == 3
    assert reduced.transformation_provenance[-1].operation == "slice_rounds"


def test_partial_boundary_reports_missing_units_exactly():
    primitive = Primitive("partial", {"state": ValueType(Bit(), (4,))})
    primitive._builder.add_round()
    copied = primitive._builder.add_component(Identity(primitive.graph.input("state"), "copy"))
    primitive._builder.set_output(copied)

    try:
        slice_primitive(primitive, copied, inputs={"known": primitive.graph.input("state")[:2]})
    except TransformationError as error:
        assert error.reason is TransformationFailureReason.DISCONNECTED_DEPENDENCY
        assert error.source_ids == ("state",)
    else:  # pragma: no cover
        raise AssertionError("incomplete boundary unexpectedly accepted")


def test_slice_preserves_structural_bindings_and_complete_composite_scopes():
    builder = CompositeBuilder("copy_block", {"value": ValueType(Bit(), (2,))})
    builder.add_round()
    copied = builder.add_component(Identity(builder.input("value"), "copy"))
    builder.set_output("output", copied)
    definition = builder.build()

    primitive = Primitive(
        "scoped",
        {"left": ValueType(Bit(), (1,)), "right": ValueType(Bit(), (1,))},
    )
    primitive._builder.add_round()
    joined = primitive._builder.join(primitive.graph.input("left"), primitive.graph.input("right"))
    instance = primitive._builder.add_composite(definition, {"value": joined}, scope_id="block")
    primitive._builder.set_output(instance.output())

    derived = slice_primitive(primitive).primitive

    assert tuple(binding.kind.value for binding in derived.graph.bindings) == ("join",)
    assert tuple(scope.path for scope in derived.graph.scopes) == ("block",)
    assert derived.evaluate(1, 0) == primitive.evaluate(1, 0) == 2
