# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8}]


class ReverseCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single bit-reversal permutation.

    INPUT:

    - ``bit_size`` -- **integer** (default: `8`); input and output bit size

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.reverse_cipher import ReverseCipher
        sage: cipher = ReverseCipher()
        sage: cipher.family_name
        'reverse_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=8):
        super().__init__(
            family_name="reverse_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        reverse_component = self.add_reverse_component([INPUT_PLAINTEXT], [list(range(bit_size))], bit_size)
        add_cipher_output_from_component(self, reverse_component)
