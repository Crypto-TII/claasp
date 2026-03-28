# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "amount_bit_size": 3, "parameter": 1}]


class VariableRotateCipher(SingleComponentCipher):
    def __init__(self, bit_size=8, amount_bit_size=3, parameter=1):
        super().__init__(
            family_name="variable_rotate_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[bit_size, amount_bit_size],
            cipher_output_bit_size=bit_size,
        )
        var_rotate_component = self.add_variable_rotate_component(
            [INPUT_PLAINTEXT, INPUT_KEY],
            [list(range(bit_size)), list(range(amount_bit_size))],
            bit_size,
            parameter,
        )
        add_cipher_output_from_component(self, var_rotate_component)
