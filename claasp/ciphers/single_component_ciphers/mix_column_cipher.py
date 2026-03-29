# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"word_size": 4, "matrix": None, "irreducible_polynomial": 0}]

_DEFAULT_MATRIX = [[1 if i == j else 0 for j in range(4)] for i in range(4)]


class MixColumnCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single MixColumn operation.

    INPUT:

    - ``word_size`` -- **integer** (default: `4`); bit size of each word (element of GF(2^word_size))
    - ``matrix`` -- **list of lists** (default: `None`); matrix with integer entries (each integer is a binary
      polynomial); defaults to the 4x4 identity matrix
    - ``irreducible_polynomial`` -- **integer** (default: `0`); integer representation of the irreducible polynomial
      over GF(2) used for field arithmetic; ``0`` means XOR-only (no field multiplication)

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.mix_column_cipher import MixColumnCipher
        sage: cipher = MixColumnCipher()
        sage: cipher.family_name
        'mix_column_cipher'
        sage: cipher.type
        'hash_function'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, word_size=4, matrix=None, irreducible_polynomial=0):
        if matrix is None:
            matrix = _DEFAULT_MATRIX
        bit_size = word_size * len(matrix)
        description = [matrix, irreducible_polynomial, word_size]
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
