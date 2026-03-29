# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "rotation_amounts_parameter": [1, 2]}]


class SigmaCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single sigma operation (XOR of multiple rotations).

    INPUT:

    - ``bit_size`` -- **integer** (default: `8`); input and output bit size
    - ``rotation_amounts_parameter`` -- **list** (default: `None`); rotation amounts; defaults to ``[1, 2]``

    EXAMPLES::

        sage: import warnings
        sage: warnings.filterwarnings('ignore', category=SyntaxWarning)
        sage: from claasp.ciphers.single_component_ciphers.sigma_cipher import SigmaCipher
        sage: cipher = SigmaCipher()
        sage: cipher.family_name
        'sigma_cipher'
        sage: cipher.type
        'hash_function'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=8, rotation_amounts_parameter=None):
        if rotation_amounts_parameter is None:
            rotation_amounts_parameter = [1, 2]
        super().__init__(
            family_name="sigma_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        sigma_component = self.add_sigma_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            rotation_amounts_parameter,
        )
        add_cipher_output_from_component(self, sigma_component)
