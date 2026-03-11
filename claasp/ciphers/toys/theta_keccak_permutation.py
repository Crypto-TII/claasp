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


class ThetaKeccakPermutation(SingleComponentToy):
    """Single-component permutation containing only a theta-keccak component.

    EXAMPLES::

        sage: from claasp.ciphers.toys.theta_keccak_permutation import ThetaKeccakPermutation
        sage: cipher = ThetaKeccakPermutation(bit_size=25)
        sage: cipher.component_from(0, 0).id
        'theta_keccak_0_0'
    """

    def __init__(self, bit_size=25):
        super().__init__("theta_keccak_permutation", "permutation", ["input"], [bit_size], bit_size)
        component = self.add_theta_keccak_component(["input"], [list(range(bit_size))], bit_size)
        self.add_component_output(component)
