# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import (
    SingleComponentCipher,
    add_cipher_output_from_component,
    build_block_cipher_inputs,
    equal_input_bit_positions,
)
from claasp.name_mappings import BLOCK_CIPHER

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 4, "number_of_inputs": 2}]


class AndCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single bitwise AND operation.

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `4`); bit size of each input word
    - ``number_of_inputs`` -- **integer** (default: `2`); number of inputs

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
        sage: cipher = AndCipher()
        sage: cipher.family_name
        'and_cipher'
        sage: cipher.type
        'block_cipher'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, word_bit_size=4, number_of_inputs=2):
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="and_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        and_component = self.add_AND_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
        )
        add_cipher_output_from_component(self, and_component)
