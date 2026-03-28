# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 4, "description": [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]}]


class LinearLayerCipher(SingleComponentCipher):
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
