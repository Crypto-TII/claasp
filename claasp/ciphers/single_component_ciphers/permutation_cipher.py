# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "permutation_description": [7, 6, 5, 4, 3, 2, 1, 0]}]


class PermutationCipher(SingleComponentCipher):
    def __init__(self, bit_size=8, permutation_description=None):
        if permutation_description is None:
            permutation_description = list(reversed(range(bit_size)))
        super().__init__(
            family_name="permutation_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        permutation_component = self.add_permutation_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            permutation_description,
        )
        add_cipher_output_from_component(self, permutation_component)
