import pytest

from claasp import Bit, Component, Port, PrimeField, Primitive, Round, ValueType


def test_logical_selection_is_independent_of_encoded_bit_size():
    state_type = ValueType(PrimeField(17), (3,))
    state = Port("state", state_type)

    selection = state.select(2, 0)

    assert selection.positions == (2, 0)
    assert selection.value_type == ValueType(PrimeField(17), (2,))
    assert selection.value_type.unit_count == 2
    assert selection.value_type.encoded_bit_size == 10


def test_selection_validates_logical_positions():
    state = Port("state", ValueType(Bit(), (4,)))

    with pytest.raises(ValueError, match="outside source"):
        state.select(4)


def test_primitive_builds_a_typed_acyclic_graph():
    state_type = ValueType(PrimeField(17), (3,))
    primitive = Primitive("toy", {"state": state_type})
    primitive_round = primitive.add_round()
    first = Component("permutation_0_0", (primitive.input("state").select(2, 0, 1),), state_type)

    first_output = primitive.add_component(first)
    second = Component("identity_0_1", (first_output.select_all(),), state_type)
    second_output = primitive.add_component(second)

    assert primitive.rounds == (primitive_round,)
    assert primitive_round.components == (first, second)
    assert primitive.components == (first, second)
    assert primitive.port("identity_0_1") == second_output


def test_primitive_rejects_a_source_from_another_graph():
    value_type = ValueType(Bit(), (4,))
    primitive = Primitive("left", {"state": value_type})
    other = Primitive("right", {"foreign": value_type})
    primitive.add_round()
    component = Component("identity_0_0", (other.input("foreign").select_all(),), value_type)

    with pytest.raises(ValueError, match="not available"):
        primitive.add_component(component)


def test_primitive_rejects_a_forged_source_type():
    primitive = Primitive("toy", {"state": ValueType(Bit(), (4,))})
    primitive.add_round()
    forged = Port("state", ValueType(PrimeField(17), (4,)))
    component = Component(
        "identity_0_0",
        (forged.select_all(),),
        ValueType(PrimeField(17), (4,)),
    )

    with pytest.raises(ValueError, match="does not match its graph port type"):
        primitive.add_component(component)


def test_primitive_rejects_duplicate_component_ids():
    value_type = ValueType(Bit(), (4,))
    primitive = Primitive("toy", {"state": value_type})
    primitive.add_round()
    component = Component("identity_0_0", (primitive.input("state").select_all(),), value_type)
    primitive.add_component(component)

    with pytest.raises(ValueError, match="already exists"):
        primitive.add_component(component)


def test_components_can_only_be_added_to_current_round():
    value_type = ValueType(Bit(), (1,))
    primitive = Primitive("toy", {"state": value_type})
    old_round = primitive.add_round()
    primitive.add_round()
    component = Component("identity_1_0", (primitive.input("state").select_all(),), value_type)

    with pytest.raises(ValueError, match="current round"):
        primitive.add_component(component, primitive_round=old_round)


def test_round_from_another_primitive_is_rejected():
    value_type = ValueType(Bit(), (1,))
    primitive = Primitive("toy", {"state": value_type})
    primitive.add_round()
    component = Component("identity_0_0", (primitive.input("state").select_all(),), value_type)

    with pytest.raises(ValueError, match="does not belong"):
        primitive.add_component(component, primitive_round=Round(0))
