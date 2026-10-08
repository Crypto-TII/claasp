import pytest

from claasp import Bit, Component, Port, PrimeField, Primitive, PrimitiveBuilder, Round, ValueType
from claasp.components import Identity


def test_logical_selection_is_independent_of_encoded_bit_size():
    state_type = ValueType(PrimeField(17), (3,))
    state = Port("state", state_type)

    selection = state.select(2, 0)

    assert selection.positions == (2, 0)
    assert selection.value_type == ValueType(PrimeField(17), (2,))
    assert selection.value_type.unit_count == 2
    assert selection.value_type.encoded_bit_size == 10


def test_builder_returns_a_completed_primitive_without_public_mutation_methods():
    value_type = ValueType(Bit(), (1,))
    builder = PrimitiveBuilder("identity", {"state": value_type})
    builder.add_round()
    output = builder.add_component(Identity(builder.input("state"), "identity_0_0"))

    primitive = builder.build(output)

    assert primitive.evaluate(1) == 1
    assert not hasattr(primitive, "add_component")
    assert not hasattr(primitive, "set_output")
    with pytest.raises(RuntimeError, match="already been built"):
        builder.add_round()


def test_completed_primitive_groups_structural_and_editing_discovery():
    from claasp.primitives import AES

    primitive = AES(number_of_rounds=2)

    assert not {
        "components",
        "rounds",
        "round_keys",
        "input",
        "add_component",
        "analyze",
        "inverse",
        "reduced_rounds",
    } & set(dir(primitive))
    assert {
        "components",
        "rounds",
        "round_keys",
        "input",
        "input_descriptor",
    } <= set(dir(primitive.graph))
    assert {
        "inverse",
        "reduce_rounds",
        "remove_key_schedule",
        "slice",
    } <= set(dir(primitive.edit))


def test_published_graph_values_have_a_concise_interactive_representation():
    from claasp.primitives import AES

    assert repr(AES(number_of_rounds=2).graph.round_keys) == (
        "Round keys (3)\n"
        "  [0] input key: 128 bits\n"
        "  [1] derived graph value: 128 bits\n"
        "  [2] derived graph value: 128 bits"
    )


def test_selection_validates_logical_positions():
    state = Port("state", ValueType(Bit(), (4,)))

    with pytest.raises(ValueError, match="outside source"):
        state.select(4)


def test_primitive_builds_a_typed_acyclic_graph():
    state_type = ValueType(PrimeField(17), (3,))
    primitive = Primitive("toy", {"state": state_type})
    primitive_round = primitive._builder.add_round()
    first = Component(
        "permutation_0_0", (primitive.graph.input("state").select(2, 0, 1),), state_type
    )

    first_output = primitive._builder.add_component(first)
    second = Component("identity_0_1", (first_output.select_all(),), state_type)
    second_output = primitive._builder.add_component(second)

    assert primitive.graph.rounds == (primitive_round,)
    assert primitive_round.components == (first, second)
    assert primitive.graph.components == (first, second)
    assert primitive.graph.port("identity_0_1") == second_output


def test_primitive_rejects_a_source_from_another_graph():
    value_type = ValueType(Bit(), (4,))
    primitive = Primitive("left", {"state": value_type})
    other = Primitive("right", {"foreign": value_type})
    primitive._builder.add_round()
    component = Component("identity_0_0", (other.graph.input("foreign").select_all(),), value_type)

    with pytest.raises(ValueError, match="not available"):
        primitive._builder.add_component(component)


def test_primitive_rejects_a_forged_source_type():
    primitive = Primitive("toy", {"state": ValueType(Bit(), (4,))})
    primitive._builder.add_round()
    forged = Port("state", ValueType(PrimeField(17), (4,)))
    component = Component(
        "identity_0_0",
        (forged.select_all(),),
        ValueType(PrimeField(17), (4,)),
    )

    with pytest.raises(ValueError, match="does not match its graph port type"):
        primitive._builder.add_component(component)


def test_primitive_rejects_duplicate_component_ids():
    value_type = ValueType(Bit(), (4,))
    primitive = Primitive("toy", {"state": value_type})
    primitive._builder.add_round()
    component = Component(
        "identity_0_0", (primitive.graph.input("state").select_all(),), value_type
    )
    primitive._builder.add_component(component)

    with pytest.raises(ValueError, match="already exists"):
        primitive._builder.add_component(component)


def test_components_can_only_be_added_to_current_round():
    value_type = ValueType(Bit(), (1,))
    primitive = Primitive("toy", {"state": value_type})
    old_round = primitive._builder.add_round()
    primitive._builder.add_round()
    component = Component(
        "identity_1_0", (primitive.graph.input("state").select_all(),), value_type
    )

    with pytest.raises(ValueError, match="current round"):
        primitive._builder.add_component(component, primitive_round=old_round)


def test_round_from_another_primitive_is_rejected():
    value_type = ValueType(Bit(), (1,))
    primitive = Primitive("toy", {"state": value_type})
    primitive._builder.add_round()
    component = Component(
        "identity_0_0", (primitive.graph.input("state").select_all(),), value_type
    )

    with pytest.raises(ValueError, match="does not belong"):
        primitive._builder.add_component(component, primitive_round=Round(0))
