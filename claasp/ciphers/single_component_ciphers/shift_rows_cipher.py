# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 8, "rotation_amount": 1, "number_of_words": 4}]


class ShiftRowsCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single ShiftRows operation.

    INPUT:

        - ``rotation_amount`` -- **integer** (default: `1`); number of words to rotate, positive for right rotation
            and negative for left rotation
        - ``word_bit_size`` -- **integer** (default: `8`); size of each word in bits
        - ``number_of_words`` -- **integer** (default: `4`); total number of words in the state

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.shift_rows_cipher import ShiftRowsCipher
        sage: cipher = ShiftRowsCipher()
        sage: cipher.family_name
        'shift_rows_cipher'
        sage: cipher.type
        'permutation'
        sage: cipher.number_of_rounds
        1
        sage: from claasp.ciphers.single_component_ciphers.shift_rows_cipher import ShiftRowsCipher
        sage: cipher = ShiftRowsCipher()
        sage: hex(cipher.evaluate([0x01020304]))
        '0x4010203'
    """
    def __init__(self, rotation_amount=1, word_bit_size=8, number_of_words=4):
        bit_size = word_bit_size * number_of_words
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
            rotation_amount,
            word_bit_size,
            number_of_words,
        )
        add_cipher_output_from_component(self, shift_rows_component)
