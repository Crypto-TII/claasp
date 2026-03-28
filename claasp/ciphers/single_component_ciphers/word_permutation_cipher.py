# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"word_size": 4, "number_of_words": 4, "permutation_description": [1, 2, 3, 0]}]


class WordPermutationCipher(SingleComponentCipher):
    def __init__(self, word_size=4, number_of_words=4, permutation_description=None):
        if permutation_description is None:
            permutation_description = [1, 2, 3, 0]
        bit_size = word_size * number_of_words
        super().__init__(
            family_name="word_permutation_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        word_permutation_component = self.add_word_permutation_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            permutation_description,
            word_size,
        )
        add_cipher_output_from_component(self, word_permutation_component)
