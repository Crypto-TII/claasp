# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 320, "rotation_amounts_parameter": [1, 18, 23, 25, 32, 52, 60, 63]}]


class ThetaGastonCipher(SingleComponentCipher):
    def __init__(self, bit_size=320, rotation_amounts_parameter=None):
        if rotation_amounts_parameter is None:
            rotation_amounts_parameter = [1, 18, 23, 25, 32, 52, 60, 63]
        super().__init__(
            family_name="theta_gaston_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        theta_component = self.add_theta_gaston_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            rotation_amounts_parameter,
        )
        add_cipher_output_from_component(self, theta_component)
