# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION

PARAMETERS_CONFIGURATION_LIST = [{"output_bit_size": 3, "value": 0b010}]


class ConstantCipher(SingleComponentCipher):
    def __init__(self, output_bit_size=3, value=0b010):
        super().__init__(
            family_name="constant_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[],
            cipher_inputs_bit_size=[],
            cipher_output_bit_size=output_bit_size,
        )
        constant_component = self.add_constant_component(output_bit_size, value)
        add_cipher_output_from_component(self, constant_component)
