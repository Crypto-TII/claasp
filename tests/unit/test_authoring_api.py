import pytest

from claasp import PrimeField, Primitive, ValueType
from claasp.components import Add, Permutation
from claasp.domains import BinaryExtensionField
from claasp.representations.execution import ScalarEvaluator
from claasp.utils import (
    binary_field_multiply,
    binary_field_power,
    repeat_block_diagonal,
    rotate_left,
)


def test_ports_support_whole_input_coercion_indexing_and_slicing():
    primitive = Primitive("authoring", {"state": ValueType(PrimeField(17), (4,))})
    state = primitive.input("state")
    assert state[3, 1].positions == (3, 1)
    assert state[1:3].positions == (1, 2)
    assert state[3, 1][1].positions == (1,)

    primitive.add_round()
    output = primitive.add_component(Permutation(state, (3, 2, 1, 0)))
    primitive.set_output(output)
    assert output.owner_id == "permutation_0_0"
    assert ScalarEvaluator().evaluate(primitive, {"state": (1, 2, 3, 4)}).output == (4, 3, 2, 1)


def test_inputs_support_named_and_positional_authoring_without_exposing_storage():
    value_type = ValueType(PrimeField(17), (1,))
    primitive = Primitive("inputs", {"left": value_type, "right": value_type})

    assert primitive.input("left") is primitive.input(0)
    assert primitive.input("right") is primitive.input(1)
    assert list(primitive.inputs()) == [primitive.input("left"), primitive.input("right")]
    assert list(primitive.inputs("right", 0)) == [primitive.input("right"), primitive.input("left")]
    assert primitive.input_ports == {"left": primitive.input(0), "right": primitive.input(1)}

    with pytest.raises(KeyError, match="does not exist"):
        primitive.input("missing")
    with pytest.raises(IndexError, match="out of range"):
        primitive.input(-1)
    with pytest.raises(IndexError, match="out of range"):
        primitive.input(2)
    with pytest.raises(TypeError, match="name or integer position"):
        primitive.input(True)


def test_round_observations_do_not_expose_authoring_collections():
    value_type = ValueType(PrimeField(17), (1,))
    primitive = Primitive("observations", {"state": value_type})
    states = [primitive.input("state")]
    published = primitive.set_round_states(states)
    states.append(primitive.input("state"))

    assert list(published) == [primitive.input("state")]
    assert primitive.round_states is published


def test_automatic_component_ids_are_deterministic_and_explicit_ids_remain_available():
    primitive = Primitive(
        "ids",
        {
            "left": ValueType(PrimeField(17), (1,)),
            "right": ValueType(PrimeField(17), (1,)),
        },
    )
    primitive.add_round()
    first = primitive.add_component(Add((primitive.input("left"), primitive.input("right"))))
    second = primitive.add_component(Add((first, primitive.input("right"))))
    named = primitive.add_component(
        Add((second, primitive.input("right")), component_id="final_sum")
    )
    assert (first.owner_id, second.owner_id, named.owner_id) == ("add_0_0", "add_0_1", "final_sum")

    with pytest.raises(ValueError, match="already exists"):
        primitive.add_component(Add((first, second), component_id="final_sum"))


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


def test_primitive_evaluate_accepts_packed_positional_keyword_and_mapping_inputs():
    from claasp.primitives import AES

    primitive = AES(number_of_rounds=1)
    plaintext = 0x00112233445566778899AABBCCDDEEFF
    key = 0x000102030405060708090A0B0C0D0E0F
    positional = primitive.evaluate(plaintext, key)
    assert primitive.evaluate(plaintext=plaintext, key=key) == positional
    assert primitive.evaluate({"plaintext": plaintext, "key": key}) == positional
    trace = primitive.evaluate_with_trace(plaintext, key)
    sub_bytes = primitive.round_states[0]["sub_bytes"]
    assert trace.value_of(sub_bytes.owner_id)
    assert positional == int.from_bytes(bytes(trace.output), "big")


def test_prime_field_scalar_is_natural_but_vectors_remain_explicit():
    from claasp.primitives import MiMC, Poseidon

    assert MiMC(17, 3, (1, 2, 4)).evaluate(5) == 5
    poseidon = Poseidon(17, 3, 2, 0, ((1, 2), (3, 4)), ((1, 1), (1, 2)))
    with pytest.raises(TypeError, match="vectors require a tuple"):
        poseidon.evaluate(1)


def test_packed_boundary_rejects_truncation_and_argument_ambiguity():
    from claasp.primitives import AES

    primitive = AES(number_of_rounds=1)
    with pytest.raises(ValueError, match="fit in 128 bits"):
        primitive.evaluate(1 << 128, 0)
    with pytest.raises(TypeError, match="do not mix"):
        primitive.evaluate(0, key=0)
