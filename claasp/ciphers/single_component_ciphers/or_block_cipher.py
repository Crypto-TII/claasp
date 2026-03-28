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


class OrBlockCipher(SingleComponentCipher):
    """
    Return a single-round cipher made of a single OR component.

    INPUT:

    - ``word_bit_size`` -- **integer** (default: `4`); bit size of each OR operand and of the output
    - ``number_of_inputs`` -- **integer** (default: `2`); number of OR operands

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.or_block_cipher import OrBlockCipher
        sage: or_cipher = OrBlockCipher(word_bit_size=4, number_of_inputs=2)
        sage: or_cipher.type
        'block_cipher'

        sage: or_cipher.component_from(0, 0).id
        'or_0_0'

        sage: or_cipher.evaluate([0b1010, 0b1100])
        14
    """

    def __init__(self, word_bit_size=4, number_of_inputs=2):
        cipher_inputs, cipher_inputs_bit_size = build_block_cipher_inputs(word_bit_size, number_of_inputs)
        super().__init__(
            family_name="or_block_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=word_bit_size,
        )
        or_component = self.add_OR_component(
            cipher_inputs,
            equal_input_bit_positions(word_bit_size, number_of_inputs),
            word_bit_size,
        )
        add_cipher_output_from_component(self, or_component)
