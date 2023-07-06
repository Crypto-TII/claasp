
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


from sage.modules.free_module_element import vector

from claasp.input import Input
from claasp.component import Component, free_input


class FSR(Component):
    def __init__(self, current_round_number, current_round_number_of_components, input_id_links,
                 input_bit_positions, output_bit_size, description):
        component_id = f'fsr_{current_round_number}_{current_round_number_of_components}'
        component_type = 'fsr'
        input_len = 0
        for bits in input_bit_positions:
            input_len = input_len + len(bits)
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)
        self.input_len = input_len

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for LFSR.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: linear_layer_component = fancy.get_component_from_id("linear_layer_0_6")
            sage: algebraic = AlgebraicModel(fancy)
            sage: L = linear_layer_component.algebraic_polynomials(algebraic)
            sage: L[0]
            linear_layer_0_6_y0 + linear_layer_0_6_x23 + linear_layer_0_6_x19 + linear_layer_0_6_x18 + linear_layer_0_6_x16 + linear_layer_0_6_x15 + linear_layer_0_6_x14 + linear_layer_0_6_x12 + linear_layer_0_6_x9 + linear_layer_0_6_x8 + linear_layer_0_6_x6 + linear_layer_0_6_x3
        """
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_R = model.ring()
        x = list(ring_R, (map(ring_R, [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)])))
        y = vector(ring_R,
                   list(map(ring_R, [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)])))
        polynomial_index_list = self.description[0]
        loop = self.description[1]

        fsr_polynomial = 0
        for _ in polynomial_index_list:
            m = 1
            for __ in _ :
                m *= x[__]
            fsr_polynomial += m

        for i in range(loop):
            output_bit = fsr_polynomial(*x)
            x = x[:-1]
            x.append(output_bit)

        output_polynomials = y+vector(x)
        return output_polynomials

    def get_bit_based_c_code(self, verbosity):
        fsr_code = []
        self.select_bits(fsr_code)
        loop = self.description[1]

        polynomial_index_list = self.description[0]
        polynomial_index_matrix = [[0 for i in range(self.input_len)] for j in range(len(polynomial_index_list))]
        for row in range(len(polynomial_index_list)):
            for i in row:
                polynomial_index_matrix[row][i] = 1

        fsr_code.append(f'\tpolynomial_matrix = (uint8_t*[][{self.input_len}]) {{')
        for row in range(len(polynomial_index_matrix)):
            fsr_code.append(f'\t\t(uint8_t[]) {{{", ".join([str(x) for x in row])}}},')
        fsr_code.append('\t};')

        fsr_code.append(f'\tBitString* {self.id} = FSR(input, polynomial_matrix, {loop});\n')

        if verbosity:
            self.print_values(fsr_code)

        free_input(fsr_code)

        return fsr_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        polynomial_index_list = self.description[0]
        loop = self.description[1]
        return [f'  {self.id} = bit_vector_fsr(bit_vector_CONCAT([{",".join(params)} ]), {polynomial_index_list}, {loop})']

    def get_byte_based_vectorized_python_code(self, params):
        polynomial_index_list = self.description[0]
        loop = self.description[1]
        return [f'  {self.id} = byte_vector_fsr({params}, {polynomial_index_list}, {loop})']




