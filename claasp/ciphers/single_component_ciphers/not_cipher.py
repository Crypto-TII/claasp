# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 4}]


class NotCipher(SingleComponentCipher):
    def __init__(self, bit_size=4):
        super().__init__(
            family_name="not_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        not_component = self.add_NOT_component([INPUT_PLAINTEXT], [list(range(bit_size))], bit_size)
        add_cipher_output_from_component(self, not_component)
