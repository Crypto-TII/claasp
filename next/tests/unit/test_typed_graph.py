import pytest

from claasp_next import Bit, Cipher, Component, Port, PrimeField, Round, ValueType


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


def test_cipher_builds_a_typed_acyclic_graph():
    state_type = ValueType(PrimeField(17), (3,))
    cipher = Cipher("toy", {"state": state_type})
    cipher_round = cipher.add_round()
    first = Component("permutation_0_0", (cipher.input("state").select(2, 0, 1),), state_type)

    first_output = cipher.add_component(first)
    second = Component("identity_0_1", (first_output.select_all(),), state_type)
    second_output = cipher.add_component(second)

    assert cipher.rounds == (cipher_round,)
    assert cipher_round.components == (first, second)
    assert cipher.components == (first, second)
    assert cipher.port("identity_0_1") == second_output


def test_cipher_rejects_a_source_from_another_graph():
    value_type = ValueType(Bit(), (4,))
    cipher = Cipher("left", {"state": value_type})
    other = Cipher("right", {"foreign": value_type})
    cipher.add_round()
    component = Component("identity_0_0", (other.input("foreign").select_all(),), value_type)

    with pytest.raises(ValueError, match="not available"):
        cipher.add_component(component)


def test_cipher_rejects_a_forged_source_type():
    cipher = Cipher("toy", {"state": ValueType(Bit(), (4,))})
    cipher.add_round()
    forged = Port("state", ValueType(PrimeField(17), (4,)))
    component = Component(
        "identity_0_0",
        (forged.select_all(),),
        ValueType(PrimeField(17), (4,)),
    )

    with pytest.raises(ValueError, match="does not match its graph port type"):
        cipher.add_component(component)


def test_cipher_rejects_duplicate_component_ids():
    value_type = ValueType(Bit(), (4,))
    cipher = Cipher("toy", {"state": value_type})
    cipher.add_round()
    component = Component("identity_0_0", (cipher.input("state").select_all(),), value_type)
    cipher.add_component(component)

    with pytest.raises(ValueError, match="already exists"):
        cipher.add_component(component)


def test_components_can_only_be_added_to_current_round():
    value_type = ValueType(Bit(), (1,))
    cipher = Cipher("toy", {"state": value_type})
    old_round = cipher.add_round()
    cipher.add_round()
    component = Component("identity_1_0", (cipher.input("state").select_all(),), value_type)

    with pytest.raises(ValueError, match="current round"):
        cipher.add_component(component, cipher_round=old_round)


def test_round_from_another_cipher_is_rejected():
    value_type = ValueType(Bit(), (1,))
    cipher = Cipher("toy", {"state": value_type})
    cipher.add_round()
    component = Component("identity_0_0", (cipher.input("state").select_all(),), value_type)

    with pytest.raises(ValueError, match="does not belong"):
        cipher.add_component(component, cipher_round=Round(0))
