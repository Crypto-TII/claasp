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


from claasp.cipher import Cipher


class SingleComponentToy(Cipher):
    def __init__(
        self,
        family_name,
        cipher_type,
        cipher_inputs,
        cipher_inputs_bit_size,
        cipher_output_bit_size,
    ):
        super().__init__(
            family_name=family_name,
            cipher_type=cipher_type,
            cipher_inputs=cipher_inputs,
            cipher_inputs_bit_size=cipher_inputs_bit_size,
            cipher_output_bit_size=cipher_output_bit_size,
        )
        self.add_round()

    def add_component_output(self, component):
        self.add_cipher_output_component(
            [component.id],
            [list(range(component.output_bit_size))],
            component.output_bit_size,
        )
