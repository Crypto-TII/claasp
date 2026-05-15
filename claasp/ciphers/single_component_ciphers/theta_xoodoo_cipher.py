# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 384}]


class ThetaXoodooCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single Theta-Xoodoo component.

    INPUT:

    - ``bit_size`` -- **integer** (default: `384`); input and output bit size

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.theta_xoodoo_cipher import ThetaXoodooCipher
        sage: cipher = ThetaXoodooCipher()
        sage: cipher.family_name
        'theta_xoodoo_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=384):
        super().__init__(
            family_name="theta_xoodoo_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        theta_component = self.add_theta_xoodoo_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
        )
        add_cipher_output_from_component(self, theta_component)
