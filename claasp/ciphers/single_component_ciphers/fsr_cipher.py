# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"register_size": 4, "description": [[[4, [[0], [1]]]], 1]}]


class FsrCipher(SingleComponentCipher):
    def __init__(self, register_size=4, description=None):
        if description is None:
            description = [[[register_size, [[0], [1]]]], 1]
        super().__init__(
            family_name="fsr_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[register_size],
            cipher_output_bit_size=register_size,
        )
        fsr_component = self.add_FSR_component(
            [INPUT_PLAINTEXT],
            [list(range(register_size))],
            register_size,
            description,
        )
        add_cipher_output_from_component(self, fsr_component)
