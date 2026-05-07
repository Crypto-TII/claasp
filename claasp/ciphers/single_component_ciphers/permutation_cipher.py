# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "permutation_description": [7, 6, 5, 4, 3, 2, 1, 0], "word_size": 1}]


class PermutationCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single bitwise permutation component.

    INPUT:

    - ``bit_size`` -- **integer** (default: `8`); input and output bit size
    - ``permutation_description`` -- **list** (default: `None`); permutation as a list; defaults to bit reversal
        - ``word_size`` -- **integer** (default: `1`); number of bits per word. Set to ``1`` for bitwise
            permutation. When ``> 1``, ``permutation_description`` should have ``bit_size // word_size`` entries.

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
        sage: cipher = PermutationCipher()
        sage: cipher.family_name
        'permutation_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=8, permutation_description=None, word_size=1):
        if permutation_description is None:
            if word_size == 1:
                permutation_description = list(reversed(range(bit_size)))
            else:
                n_words = bit_size // word_size
                permutation_description = list(reversed(range(n_words)))
        super().__init__(
            family_name="permutation_cipher",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        permutation_component = self.add_permutation_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            permutation_description,
                    word_size,
        )
        add_cipher_output_from_component(self, permutation_component)
