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
