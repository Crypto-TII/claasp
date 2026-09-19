from claasp_next import (
    Bit,
    Primitive,
    PrimitiveKind,
    ValueType,
    Word,
    inline_reorderings,
    prune_orphans,
    remove_key_schedule,
)
from claasp_next.components import Identity, LinearMap, Permutation, Rotate, Shift, Xor
from claasp_next.graph import as_selection
from claasp_next.primitives import Present, Speck

PLAINTEXT = 0x6574694C
KEY = 0x1918111009080100


def _published_values(primitive, observations, trace):
    cache = {}
    return tuple(
        primitive.resolve_selection(as_selection(observation), trace.values, cache)
        for observation in observations
    )


def test_remove_key_schedule_externalizes_round_keys_and_preserves_evaluation():
    primitive = Speck(number_of_rounds=4)
    trace = primitive.evaluate_with_trace(PLAINTEXT, KEY)
    round_keys = _published_values(primitive, primitive.round_keys, trace)
    result = remove_key_schedule(primitive)
    transformed = result.primitive
    supplied = {"plaintext": PLAINTEXT}
    supplied.update((f"round_key_{index}", value) for index, value in enumerate(round_keys))

    assert transformed.evaluate(**supplied) == primitive.evaluate(PLAINTEXT, KEY)
    assert tuple(transformed.input_ports) == (
        "plaintext",
        "round_key_0",
        "round_key_1",
        "round_key_2",
        "round_key_3",
    )
    assert transformed.secret_inputs == ("round_key_0", "round_key_1", "round_key_2", "round_key_3")
    assert transformed.kind is PrimitiveKind.BLOCK_CIPHER
    assert transformed.transformation_provenance[-1].operation == "remove_key_schedule"
    assert primitive.transformation_provenance == ()


def test_remove_key_schedule_without_injections_matches_zero_round_keys():
    primitive = Speck(number_of_rounds=4)
    retained = primitive.without_key_schedule().primitive
    removed = primitive.without_key_schedule(keep_round_key_injection=False).primitive
    zero_keys = {name: 0 for name in retained.input_ports if name.startswith("round_key_")}

    assert tuple(removed.input_ports) == ("plaintext",)
    assert removed.evaluate(PLAINTEXT) == retained.evaluate(plaintext=PLAINTEXT, **zero_keys)
    assert removed.kind is PrimitiveKind.FUNCTION
    assert all(
        not any(item.source.owner_id.startswith("round_key_") for item in component.inputs)
        for component in removed.components
    )


def test_prune_orphans_reconstructs_only_the_output_dependency_closure():
    graph = Primitive(
        "orphans",
        {"left": ValueType(Word(8), (1,)), "right": ValueType(Word(8), (1,))},
    )
    graph.add_round()
    output = graph.add_component(Xor(graph.inputs()), primitive_round=graph.rounds[-1])
    graph.add_component(Shift(graph.input("left"), 1, "left"))
    graph.set_output(output)

    pruned = prune_orphans(graph).primitive

    assert pruned.evaluate(0xA5, 0x3C) == graph.evaluate(0xA5, 0x3C)
    assert len(pruned.components) == 1
    assert pruned.transformation_provenance[-1].operation == "prune_orphans"


def test_inline_reorderings_preserves_speck_and_present_semantics():
    cases = (
        (Speck(number_of_rounds=2), (PLAINTEXT, KEY)),
        (Present(number_of_rounds=2), (0, 0)),
    )
    for primitive, arguments in cases:
        transformed = inline_reorderings(primitive).primitive
        assert transformed.evaluate(*arguments) == primitive.evaluate(*arguments)
        assert not any(
            isinstance(component, (Permutation, Rotate)) for component in transformed.components
        )
        assert not any(isinstance(component, Identity) for component in transformed.components)
        assert transformed.bindings


def test_inline_reorderings_only_removes_permutation_matrices():
    graph = Primitive("linear", {"state": ValueType(Bit(), (3,))}, kind=PrimitiveKind.PERMUTATION)
    graph.add_round()
    reordered = graph.add_component(
        LinearMap(
            graph.input("state"),
            ((0, 1, 0), (0, 0, 1), (1, 0, 0)),
        )
    )
    mixed = graph.add_component(
        LinearMap(
            reordered,
            ((1, 1, 0), (0, 1, 0), (0, 0, 1)),
        )
    )
    graph.set_output(mixed)

    transformed = graph.with_inlined_reorderings().primitive

    assert transformed.evaluate(0b101) == graph.evaluate(0b101)
    assert sum(isinstance(component, LinearMap) for component in transformed.components) == 1
    assert tuple(binding.kind.value for binding in transformed.bindings) == ("view",)


def test_public_round_reduction_method_uses_published_round_boundaries():
    primitive = Speck(number_of_rounds=3)
    reduced = primitive.reduced_rounds(2).primitive
    assert reduced.evaluate(PLAINTEXT, KEY) == primitive.sliced(
        primitive.round_states[1]
    ).primitive.evaluate(PLAINTEXT, KEY)
