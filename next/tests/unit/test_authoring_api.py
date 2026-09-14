import pytest

from claasp_next import Cipher, PrimeField, ValueType
from claasp_next.components import Add, Permutation
from claasp_next.representations.execution import ScalarEvaluator
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


def test_cipher_evaluate_accepts_packed_positional_keyword_and_mapping_inputs():
    from claasp_next.ciphers import AESBlockCipher

    cipher = AESBlockCipher(number_of_rounds=1)
    plaintext = 0x00112233445566778899AABBCCDDEEFF
    key = 0x000102030405060708090A0B0C0D0E0F
    positional = cipher.evaluate(plaintext, key)
    assert cipher.evaluate(plaintext=plaintext, key=key) == positional
    assert cipher.evaluate({"plaintext": plaintext, "key": key}) == positional
    trace = cipher.evaluate_with_trace(plaintext, key)
    assert trace.value_of("sub_bytes_1")
    assert positional == int.from_bytes(bytes(trace.output), "big")


def test_prime_field_scalar_is_natural_but_vectors_remain_explicit():
    from claasp_next.ciphers import MiMCPermutation, PoseidonPermutation

    assert MiMCPermutation(17, 3, (1, 2, 4)).evaluate(5) == 5
    poseidon = PoseidonPermutation(17, 3, 2, 0, ((1, 2), (3, 4)), ((1, 1), (1, 2)))
    with pytest.raises(TypeError, match="vectors require a tuple"):
        poseidon.evaluate(1)


def test_packed_boundary_rejects_truncation_and_argument_ambiguity():
    from claasp_next.ciphers import AESBlockCipher

    cipher = AESBlockCipher(number_of_rounds=1)
    with pytest.raises(ValueError, match="fit in 128 bits"):
        cipher.evaluate(1 << 128, 0)
    with pytest.raises(TypeError, match="do not mix"):
        cipher.evaluate(0, key=0)
