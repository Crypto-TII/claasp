import pytest

from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
from claasp.ciphers.single_component_ciphers._base import build_block_cipher_inputs


def test_and_cipher_properties():
    cipher = AndCipher(word_bit_size=4, number_of_inputs=3)
    a, b, c = 0b1010, 0b1100, 0b0111
    assert cipher.type == "block_cipher"
    assert cipher.number_of_rounds == 1
    assert cipher.evaluate([a, b, c]) == cipher.evaluate([c, b, a])


def test_build_block_cipher_inputs_requires_at_least_two_inputs():
    with pytest.raises(ValueError, match="at least 2"):
        build_block_cipher_inputs(8, 1)
