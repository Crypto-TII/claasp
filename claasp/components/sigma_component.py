
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
from claasp.cipher_modules.generic_functions import SIGMA
from claasp.component import linear_layer_to_binary_matrix
from claasp.components.linear_layer_component import LinearLayer


class Sigma(LinearLayer):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, rotation_amounts_parameter, suffix=''):
        binary_matrix = linear_layer_to_binary_matrix(SIGMA, output_bit_size, output_bit_size, [rotation_amounts_parameter])
        description = list(binary_matrix.transpose())
        super().__init__(current_round_number, current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, description, suffix)
        self._id = f'sigma_{current_round_number}_{current_round_number_of_components}{suffix}'
        self._input = Input(output_bit_size, input_id_links, input_bit_positions)
