# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"word_size": 4, "number_of_words": 4}]


class MixColumnCipher(SingleComponentCipher):
    def __init__(self, word_size=4, number_of_words=4):
        bit_size = word_size * number_of_words
        matrix = [[1 if i == j else 0 for j in range(number_of_words)] for i in range(number_of_words)]
        description = [matrix, 0, word_size]
        super().__init__(
            family_name="mix_column_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        mix_column_component = self.add_mix_column_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            description,
        )
        add_cipher_output_from_component(self, mix_column_component)
