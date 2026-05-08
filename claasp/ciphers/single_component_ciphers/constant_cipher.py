# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION

PARAMETERS_CONFIGURATION_LIST = [{"output_bit_size": 3, "value": 0b010}]


class ConstantCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single constant component.

    INPUT:

    - ``output_bit_size`` -- **integer** (default: `3`); number of output bits
    - ``value`` -- **integer** (default: `0b010`); constant value to output

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
        sage: cipher = ConstantCipher()
        sage: cipher.family_name
        'constant_cipher'
        sage: cipher.type
        'hash_function'
        sage: cipher.number_of_rounds
        1
    """
    def __init__(self, output_bit_size=3, value=0b010):
        super().__init__(
            family_name="constant_cipher",
            cipher_type=HASH_FUNCTION,
            cipher_inputs=[],
            cipher_inputs_bit_size=[],
            cipher_output_bit_size=output_bit_size,
        )
        constant_component = self.add_constant_component(output_bit_size, value)
        add_cipher_output_from_component(self, constant_component)
