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

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 4, "number_of_inputs": 2, "modulus": None}]


class ModaddCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single modular addition component (with modulo ``2^n``).

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `4`); bit size of each input word
    - ``number_of_inputs`` -- **integer** (default: `2`); number of inputs
    - ``modulus`` -- **integer** (default: `None`); modulus; defaults to ``2^word_bit_size``

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
        sage: cipher = ModaddCipher()
        sage: cipher.family_name
        'modadd_cipher'
        sage: cipher.type
        'block_cipher'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, word_bit_size=4, number_of_inputs=2, modulus=None):
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="modadd_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        modadd_component = self.add_MODADD_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
            modulus,
        )
        add_cipher_output_from_component(self, modadd_component)
