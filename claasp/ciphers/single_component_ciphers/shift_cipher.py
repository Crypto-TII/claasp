# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "parameter": 1}]


class ShiftCipher(SingleComponentCipher):
    def __init__(self, bit_size=8, parameter=1):
        super().__init__(
            family_name="shift_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        shift_component = self.add_SHIFT_component([INPUT_PLAINTEXT], [list(range(bit_size))], bit_size, parameter)
        add_cipher_output_from_component(self, shift_component)
