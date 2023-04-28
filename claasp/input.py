
# ****************************************************************************
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


class Input:
    def __init__(self, input_bit_size, id_links, bit_positions):
        self._bit_size = input_bit_size
        self._id_links = id_links
        self._bit_positions = bit_positions

    def set_input_id_links(self, id_links):
        self._id_links = id_links

    def set_input_bit_positions(self, bit_positions):
        self._bit_positions = bit_positions

    @property
    def bit_positions(self):
        return self._bit_positions

    @property
    def bit_size(self):
        return self._bit_size

    @property
    def id_links(self):
        return self._id_links
