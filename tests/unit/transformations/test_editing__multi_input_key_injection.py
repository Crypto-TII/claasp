"""Removing key injection retains every data operand of multi-input XOR."""

import pytest

from claasp.primitives import Simon
from claasp.transformations import remove_key_schedule


@pytest.mark.parametrize("plaintext", [0, 1, 0x12345678, 0xFFFFFFFF])
def test_simon_keyless_xor_preserves_both_data_operands(plaintext):
    primitive = Simon(number_of_rounds=4)
    with_keys = remove_key_schedule(primitive, keep_round_key_injection=True).primitive
    without_keys = remove_key_schedule(primitive, keep_round_key_injection=False).primitive
    inputs = {name: 0 for name in with_keys.graph.input_arrays}
    inputs["plaintext"] = plaintext
    assert tuple(without_keys.graph.input_arrays) == ("plaintext",)
    assert without_keys.evaluate(plaintext) == with_keys.evaluate(**inputs)
