# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "parameter": 1}]


class RotateCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single rotation.

    INPUT:

    - ``bit_size`` -- **integer** (default: `8`); input and output bit size
    - ``parameter`` -- **integer** (default: `1`); rotation amount (positive = left, negative = right)

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
        sage: cipher = RotateCipher()
        sage: cipher.family_name
        'rotate_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=8, parameter=1):
        super().__init__(
            family_name="rotate_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        rotate_component = self.add_rotate_component([INPUT_PLAINTEXT], [list(range(bit_size))], bit_size, parameter)
        add_cipher_output_from_component(self, rotate_component)
