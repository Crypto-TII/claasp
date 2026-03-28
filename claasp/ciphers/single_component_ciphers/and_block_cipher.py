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

PARAMETERS_CONFIGURATION_LIST = [{"word_bit_size": 4, "number_of_inputs": 2}]


class AndBlockCipher(SingleComponentCipher):
    """
    Return a single-round cipher made of a single AND component.

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `4`); bit size of each AND operand and of the output
    - ``number_of_inputs`` -- **integer** (default: `2`); number of AND operands

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.and_block_cipher import AndBlockCipher
        sage: and_cipher = AndBlockCipher(word_bit_size=4, number_of_inputs=2)
        sage: and_cipher.type
        'block_cipher'

        sage: and_cipher.component_from(0, 0).id
        'and_0_0'

        sage: and_cipher.evaluate([0b1010, 0b1100])
        8
    """

    def __init__(self, word_bit_size=4, number_of_inputs=2):
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="and_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        and_component = self.add_AND_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
        )
        add_cipher_output_from_component(self, and_component)
