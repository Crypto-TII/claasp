# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 25}]


class ThetaKeccakCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single Theta-Keccak component.

    INPUT:

    - ``bit_size`` -- **integer** (default: `25`); input and output bit size

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.theta_keccak_cipher import ThetaKeccakCipher
        sage: cipher = ThetaKeccakCipher()
        sage: cipher.family_name
        'theta_keccak_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=25):
        super().__init__(
            family_name="theta_keccak_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        theta_component = self.add_theta_keccak_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
        )
        add_cipher_output_from_component(self, theta_component)
