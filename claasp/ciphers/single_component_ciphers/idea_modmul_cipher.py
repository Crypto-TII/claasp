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

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 16, "number_of_inputs": 2, "modulus": 65537}]


class IdeaModmulCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single IDEA multiplication modulo ``2^n + 1``.

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `16`); bit size of each input word
    - ``number_of_inputs`` -- **integer** (default: `2`); number of inputs
    - ``modulus`` -- **integer** (default: `None`); modulus; defaults to ``2^word_bit_size + 1``

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.idea_modmul_cipher import IdeaModmulCipher
        sage: cipher = IdeaModmulCipher()
        sage: cipher.family_name
        'idea_modmul_cipher'
        sage: cipher.type
        'block_cipher'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, word_bit_size=16, number_of_inputs=2, modulus=None):
        if modulus is None:
            modulus = (1 << word_bit_size) + 1
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="idea_modmul_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        idea_modmul_component = self.add_idea_modmul_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
            modulus,
        )
        add_cipher_output_from_component(self, idea_modmul_component)
