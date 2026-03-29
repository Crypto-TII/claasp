# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import (
    SingleComponentCipher,
    add_cipher_output_from_component,
    build_block_cipher_inputs,
    equal_input_bit_positions,
)
from claasp.name_mappings import BLOCK_CIPHER

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 4, "number_of_inputs": 2}]


class XorCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single XOR operation.

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `4`); bit size of each input word
    - ``number_of_inputs`` -- **integer** (default: `2`); number of inputs

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
        sage: cipher = XorCipher()
        sage: cipher.family_name
        'xor_cipher'
        sage: cipher.type
        'block_cipher'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, word_bit_size=4, number_of_inputs=2):
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="xor_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        xor_component = self.add_XOR_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
        )
        add_cipher_output_from_component(self, xor_component)
