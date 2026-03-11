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


class OrBlockCipher(SingleComponentToy):
    """Single-round block cipher containing only an OR component.

    EXAMPLES::

        sage: from claasp.ciphers.toys.or_block_cipher import OrBlockCipher
        sage: cipher = OrBlockCipher(block_bit_size=32)
        sage: cipher.component_from(0, 0).id
        'or_0_0'
    """

    def __init__(self, block_bit_size=32):
        super().__init__("or_block_cipher", "block_cipher", ["input1", "input2"], [block_bit_size, block_bit_size], block_bit_size)
        component = self.add_OR_component(["input1", "input2"], [list(range(block_bit_size)), list(range(block_bit_size))], block_bit_size)
        self.add_component_output(component)
