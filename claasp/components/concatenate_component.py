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


from claasp.input import Input
from claasp.component import Component
from claasp.name_mappings import CONCATENATE


class Concatenate(Component):
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
    ):
        component_id = f"{CONCATENATE}_{current_round_number}_{current_round_number_of_components}"
        component_type = CONCATENATE
        description = ["", 0]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def get_bit_based_c_code(self, verbosity):
        concatenate_code = []
        self.select_bits(concatenate_code)

        concatenate_code.append(f"\tBitString *{self.id} = input;")

        if verbosity:
            self.print_values(concatenate_code)

        return concatenate_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f"  {self.id} = bit_vector_CONCAT([{','.join(params)} ])"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = np.vstack({params})"]

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        concatenate_code = []
        self.select_words(concatenate_code, word_size, False)
        wordstring_variables.append(self.id)

        if verbosity:
            concatenate_code.append(f"\tstr = wordstring_to_hex_string({self.id});")
            concatenate_code.append(f'\tprintf("{self.id} input: %s\\n", str);')
            concatenate_code.append(f'\tprintf("{self.id} output: %s\\n", str);')
            concatenate_code.append("\tfree(str);")

        return concatenate_code
