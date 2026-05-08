# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
# ****************************************************************************

from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"register_size": 4, "description": [[[4, [[0], [1]]]], 1]}]


class FsrCipher(SingleComponentCipher):
    """
    Return a cipher object containing a single FSR (Feedback Shift Register) component.

    INPUT:

    - ``register_size`` -- **integer** (default: `4`); size of the shift register in bits
    - ``description`` -- **list** (default: `None`); FSR description; defaults to a 2-tap LFSR

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.fsr_cipher import FsrCipher
        sage: cipher = FsrCipher()
        sage: cipher.family_name
        'fsr_cipher'
        sage: cipher.type
        'hash_function'
        sage: cipher.number_of_rounds
        1
    """
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
        fsr_component = self.add_fsr_component(
            [INPUT_PLAINTEXT],
            [list(range(register_size))],
            register_size,
            description,
        )
        add_cipher_output_from_component(self, fsr_component)
