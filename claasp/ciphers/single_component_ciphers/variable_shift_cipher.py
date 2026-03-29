# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 8, "amount_bit_size": 3, "direction": 1}]


class VariableShiftCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single variable shift (amount given as input).

    INPUT:

    - ``bit_size`` -- **integer** (default: `8`); input and output bit size
    - ``amount_bit_size`` -- **integer** (default: `3`); bit size of the shift amount input
    - ``direction`` -- **integer** (default: `1`); direction (positive = left, negative = right)

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.variable_shift_cipher import VariableShiftCipher
        sage: cipher = VariableShiftCipher()
        sage: cipher.family_name
        'variable_shift_cipher'
        sage: cipher.type
        'hash_function'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, bit_size=8, amount_bit_size=3, direction=1):
        super().__init__(
            family_name="variable_shift_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[bit_size, amount_bit_size],
            cipher_output_bit_size=bit_size,
        )
        var_shift_component = self.add_variable_shift_component(
            [INPUT_PLAINTEXT, INPUT_KEY],
            [list(range(bit_size)), list(range(amount_bit_size))],
            bit_size,
            direction,
        )
        add_cipher_output_from_component(self, var_shift_component)
