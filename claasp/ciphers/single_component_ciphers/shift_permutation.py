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


from claasp.ciphers.single_component_ciphers._base import SingleComponentCipher, add_cipher_output_from_component
from claasp.name_mappings import INPUT_PLAINTEXT, PERMUTATION

PARAMETERS_CONFIGURATION_LIST = [{"bit_size": 4, "parameter": 1}]


class ShiftPermutation(SingleComponentCipher):
    """
    Return a single-round wrapper around a single SHIFT component.

    INPUT:

    - ``bit_size`` -- **integer** (default: `4`); bit size of the input and output
    - ``parameter`` -- **integer** (default: `1`); shift amount, positive for right and negative for left

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.shift_permutation import ShiftPermutation
        sage: shift = ShiftPermutation(bit_size=4, parameter=1)
        sage: shift.type
        'permutation'

        sage: shift.component_from(0, 0).id
        'shift_0_0'

        sage: shift.evaluate([0b1010])
        5
    """

    def __init__(self, bit_size=4, parameter=1):
        super().__init__(
            family_name="shift_permutation",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        shift_component = self.add_SHIFT_component([INPUT_PLAINTEXT], [list(range(bit_size))], bit_size, parameter)
        add_cipher_output_from_component(self, shift_component)
