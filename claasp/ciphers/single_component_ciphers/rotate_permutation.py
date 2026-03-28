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


class RotatePermutation(SingleComponentCipher):
    """
    Return a single-round permutation made of a single ROTATE component.

    INPUT:

    - ``bit_size`` -- **integer** (default: `4`); bit size of the input and output
    - ``parameter`` -- **integer** (default: `1`); rotation amount, positive for right and negative for left

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.rotate_permutation import RotatePermutation
        sage: rotate = RotatePermutation(bit_size=4, parameter=1)
        sage: rotate.type
        'permutation'

        sage: rotate.component_from(0, 0).id
        'rot_0_0'

        sage: rotate.evaluate([0b1010])
        5
    """

    def __init__(self, bit_size=4, parameter=1):
        super().__init__(
            family_name="rotate_permutation",
            cipher_type=PERMUTATION,
            cipher_inputs=[INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[bit_size],
            cipher_output_bit_size=bit_size,
        )
        rotate_component = self.add_rotate_component([INPUT_PLAINTEXT], [list(range(bit_size))], bit_size, parameter)
        add_cipher_output_from_component(self, rotate_component)
