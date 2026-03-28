# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


from claasp.ciphers.single_component_ciphers._base import (
    SingleComponentCipher,
    add_cipher_output_from_component,
    build_block_cipher_inputs,
    equal_input_bit_positions,
)
from claasp.name_mappings import BLOCK_CIPHER

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 4, "number_of_inputs": 2, "modulus": None}]


class ModaddBlockCipher(SingleComponentCipher):
    """
    Return a single-round cipher made of a single modular-addition component.

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `4`); bit size of each addend and of the output
    - ``number_of_inputs`` -- **integer** (default: `2`); number of addends
    - ``modulus`` -- **integer** (default: `None`); optional modulus override

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.modadd_block_cipher import ModaddBlockCipher
        sage: modadd = ModaddBlockCipher(word_bit_size=4, number_of_inputs=2, modulus=16)
        sage: modadd.type
        'block_cipher'

        sage: modadd.component_from(0, 0).id
        'modadd_0_0'

        sage: modadd.evaluate([7, 9])
        0
    """

    def __init__(self, word_bit_size=4, number_of_inputs=2, modulus=None):
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="modadd_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        modadd_component = self.add_MODADD_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
            modulus,
        )
        add_cipher_output_from_component(self, modadd_component)
