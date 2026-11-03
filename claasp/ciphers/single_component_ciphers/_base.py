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
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT


def add_cipher_output_from_component(cipher, component):
    cipher.add_cipher_output_component([component.id], [list(range(component.output_bit_size))], component.output_bit_size)


def build_block_cipher_inputs(word_bit_size, number_of_inputs):
    if number_of_inputs < 2:
        raise ValueError("number_of_inputs must be at least 2 for a block cipher")

    cipher_inputs = [INPUT_PLAINTEXT, INPUT_KEY]
    for input_index in range(2, number_of_inputs):
        cipher_inputs.append(f"key_{input_index - 1}")

    return cipher_inputs, [word_bit_size] * number_of_inputs


def equal_input_bit_positions(word_bit_size, number_of_inputs):
    return [list(range(word_bit_size)) for _ in range(number_of_inputs)]


class SingleComponentCipher(Cipher):
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
