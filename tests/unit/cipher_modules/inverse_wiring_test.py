"""Exhaustive inverse checks for reordered and duplicated known-operand bits."""

import pytest
from claasp.cipher import Cipher


@pytest.mark.parametrize("wiring", [[2, 0, 3, 1], [2, 0, 2, 1]])
def test_inverse_preserves_known_xor_operand_bit_order(wiring):
    cipher = Cipher("reordered_known_xor", "permutation", ["plaintext"], [8], 8)
    cipher.add_round()
    nonlinear = cipher.add_and_component(
        ["plaintext", "plaintext"], [[0, 1, 2, 3], [1, 2, 3, 0]], 4
    )
    mixed = cipher.add_xor_component(
        [nonlinear.id, "plaintext"], [wiring, [4, 5, 6, 7]], 4
    )
    cipher.add_cipher_output_component(
        ["plaintext", mixed.id], [[0, 1, 2, 3], [0, 1, 2, 3]], 8
    )
    inverse = cipher.cipher_inverse()
    for plain in range(256):
        assert inverse.evaluate([cipher.evaluate([plain])]) == plain


def test_inverse_module_preserves_key_schedule_helper_export():
    from claasp.cipher_modules.inverse_cipher import get_key_schedule_component_ids
    from claasp.editor import get_key_schedule_component_ids as editor_helper

    assert get_key_schedule_component_ids is editor_helper


@pytest.mark.parametrize('direction',[-1,1])
def test_inverse_variable_rotation_with_recovered_data_dependent_amount(direction):
    cipher=Cipher('triangular_variable_rotation','permutation',['plaintext'],[8],8)
    cipher.add_round()
    rotated=cipher.add_variable_rotate_component(
        ['plaintext','plaintext'],[[4,5,6,7],[2,0,3,1]],4,direction)
    cipher.add_cipher_output_component(['plaintext',rotated.id],[[0,1,2,3],[0,1,2,3]],8)
    inverse=cipher.cipher_inverse()
    for plain in range(256):
        assert inverse.evaluate([cipher.evaluate([plain])])==plain


def test_rc5_inverse_uses_known_rotation_amounts():
    import random
    from claasp.ciphers.block_ciphers.rc5_block_cipher import RC5BlockCipher
    cipher=RC5BlockCipher(number_of_rounds=4)
    inverse=cipher.cipher_inverse()
    rng=random.Random(20261122)
    for _ in range(16):
        key,plain=rng.getrandbits(64),rng.getrandbits(32)
        ciphertext=cipher.evaluate([key,plain])
        reverse=[key if name=='key' else ciphertext for name in inverse.inputs]
        assert inverse.evaluate(reverse)==plain
