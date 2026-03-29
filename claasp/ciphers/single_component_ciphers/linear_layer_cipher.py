# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 4, "description": [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]}]


class LinearLayerCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single linear layer (matrix multiplication over GF(2)).

    INPUT:

    - ``bit_size`` -- **integer** (default: `4`); input and output bit size
    - ``description`` -- **list of lists** (default: `None`); binary matrix; defaults to the identity

    EXAMPLES::

        sage: import warnings
        sage: warnings.filterwarnings('ignore', category=SyntaxWarning)
        sage: from claasp.ciphers.single_component_ciphers.linear_layer_cipher import LinearLayerCipher
        sage: cipher = LinearLayerCipher()
        sage: cipher.family_name
        'linear_layer_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=4, description=None):
        if description is None:
            description = [[1 if i == j else 0 for j in range(bit_size)] for i in range(bit_size)]
        super().__init__(
            family_name="linear_layer_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        linear_layer_component = self.add_linear_layer_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            description,
        )
        add_cipher_output_from_component(self, linear_layer_component)
