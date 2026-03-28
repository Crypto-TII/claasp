# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 16, "parameter": 4}]


class ShiftRowsCipher(SingleComponentCipher):
    def __init__(self, bit_size=16, parameter=4):
        super().__init__(
            family_name="shift_rows_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        shift_rows_component = self.add_shift_rows_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            parameter,
        )
        add_cipher_output_from_component(self, shift_rows_component)
