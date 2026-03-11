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


from claasp.ciphers.toys.single_component_toy import SingleComponentToy


class RotatePermutation(SingleComponentToy):
    """Single-round permutation containing only a rotate component.

    EXAMPLES::

        sage: from claasp.ciphers.toys.rotate_permutation import RotatePermutation
        sage: cipher = RotatePermutation(bit_size=8, parameter=-3)
        sage: cipher.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, bit_size=8, parameter=-3):
        super().__init__("rotate_permutation", "permutation", ["input"], [bit_size], bit_size)
        component = self.add_rotate_component(["input"], [list(range(bit_size))], bit_size, parameter)
        self.add_component_output(component)
