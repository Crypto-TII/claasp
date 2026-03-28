# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import PERMUTATION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 384}]


class ThetaXoodooCipher(SingleComponentCipher):
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
