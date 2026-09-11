import pytest

from claasp_next import Cipher, PrimeField, ValueType
from claasp_next.components import Add, Permutation
from claasp_next.evaluators import ScalarEvaluator
from claasp_next.utils import (
    binary_field_multiply,
    binary_field_power,
    repeat_block_diagonal,
    rotate_left,
)
from claasp_next.domains import BinaryExtensionField


def test_ports_support_whole_input_coercion_indexing_and_slicing():
    cipher = Cipher("authoring", {"state": ValueType(PrimeField(17), (4,))})
    state = cipher.input("state")
    assert state[3, 1].positions == (3, 1)
    assert state[1:3].positions == (1, 2)
    assert state[3, 1][1].positions == (1,)

    cipher.add_round()
    output = cipher.add_component(Permutation(state, (3, 2, 1, 0)))
    cipher.set_output(output)
    assert output.owner_id == "permutation_0_0"
    assert ScalarEvaluator().evaluate(cipher, {"state": (1, 2, 3, 4)}).output == (4, 3, 2, 1)


def test_automatic_component_ids_are_deterministic_and_explicit_ids_remain_available():
    cipher = Cipher("ids", {
        "left": ValueType(PrimeField(17), (1,)),
        "right": ValueType(PrimeField(17), (1,)),
    })
    cipher.add_round()
    first = cipher.add_component(Add((cipher.input("left"), cipher.input("right"))))
    second = cipher.add_component(Add((first, cipher.input("right"))))
    named = cipher.add_component(Add((second, cipher.input("right")), component_id="final_sum"))
    assert (first.owner_id, second.owner_id, named.owner_id) == (
        "add_0_0", "add_0_1", "final_sum"
    )

    with pytest.raises(ValueError, match="already exists"):
        cipher.add_component(Add((first, second), component_id="final_sum"))


def test_reusable_finite_field_integer_and_matrix_helpers():
    field = BinaryExtensionField(8, 0x11B)
    assert binary_field_multiply(field, 0x57, 0x13) == 0xFE
    assert binary_field_power(field, 0x53, 254) == 0xCA
    assert rotate_left(0x81, 1, 8) == 0x03
    assert repeat_block_diagonal(((1, 2), (3, 4)), 2) == (
        (1, 2, 0, 0),
        (3, 4, 0, 0),
        (0, 0, 1, 2),
        (0, 0, 3, 4),
    )
