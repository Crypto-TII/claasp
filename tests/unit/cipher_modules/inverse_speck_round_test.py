"""Regression checks for a keyless, Speck-style ARX round."""

import numpy as np
import pytest

from claasp.cipher import Cipher
from claasp.name_mappings import PERMUTATION


def _mini_speck(number_of_rounds):
    cipher = Cipher("mini_speck", PERMUTATION, ["plaintext"], [8], 8)
    state = "plaintext"
    word_bits = list(range(4))
    for _ in range(number_of_rounds):
        cipher.add_round()
        rotated_x = cipher.add_rotate_component(
            [state], [word_bits], 4, 1
        )
        new_x = cipher.add_modadd_component(
            [rotated_x.id, state],
            [word_bits, list(range(4, 8))],
            4,
        )
        rotated_y = cipher.add_rotate_component(
            [state], [list(range(4, 8))], 4, -2
        )
        new_y = cipher.add_xor_component(
            [rotated_y.id, new_x.id],
            [word_bits, word_bits],
            4,
        )
        state = cipher.add_round_output_component(
            [new_x.id, new_y.id], [word_bits, word_bits], 8
        ).id
    cipher.add_cipher_output_component([state], [list(range(8))], 8)
    return cipher


@pytest.mark.parametrize("number_of_rounds", [1, 2])
def test_mini_speck_inverse_scalar_and_vectorized(number_of_rounds):
    cipher = _mini_speck(number_of_rounds)
    inverse = cipher.cipher_inverse()
    plaintexts = np.arange(256, dtype=np.uint8)
    ciphertexts = np.array(
        [cipher.evaluate([int(value)]) for value in plaintexts],
        dtype=np.uint8,
    )

    for plain, crypt in zip(plaintexts, ciphertexts):
        assert inverse.evaluate([int(crypt)]) == int(plain)

    vectorized = inverse.evaluate_vectorized(
        [ciphertexts.reshape(1, -1)]
    )[0]
    assert np.array_equal(vectorized.reshape(-1), plaintexts)
    assert inverse.evaluate_vectorized(
        [ciphertexts.tolist()], evaluate_api=True
    ) == plaintexts.tolist()
