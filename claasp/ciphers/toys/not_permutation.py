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


class NotPermutation(SingleComponentToy):
    """Single-round permutation containing only a NOT component.

    EXAMPLES::

        sage: from claasp.ciphers.toys.not_permutation import NotPermutation
        sage: cipher = NotPermutation(bit_size=8)
        sage: cipher.component_from(0, 0).id
        'not_0_0'
    """

    def __init__(self, bit_size=8):
        super().__init__("not_permutation", "permutation", ["input"], [bit_size], bit_size)
        component = self.add_NOT_component(["input"], [list(range(bit_size))], bit_size)
        self.add_component_output(component)
