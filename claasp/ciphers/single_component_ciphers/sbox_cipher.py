# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 4, "lookup_table": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]}]


class SboxCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single S-box lookup.

    INPUT:

    - ``bit_size`` -- **integer** (default: `4`); input and output bit size
    - ``lookup_table`` -- **list** (default: `None`); lookup table of length ``2^bit_size``; defaults to the identity table

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
        sage: cipher = SboxCipher()
        sage: cipher.family_name
        'sbox_cipher'
        sage: cipher.type
        'hash_function'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=4, lookup_table=None):
        if lookup_table is None:
            lookup_table = list(range(2**bit_size))
        super().__init__(
            family_name="sbox_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        sbox_component = self.add_SBOX_component(
            [INPUT_PLAINTEXT],
            [list(range(bit_size))],
            bit_size,
            lookup_table,
        )
        add_cipher_output_from_component(self, sbox_component)
