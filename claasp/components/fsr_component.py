
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
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.input import Input
from claasp.component import Component, free_input
# from claasp.utils.utils import bits_to_words_array, words_array_to_bits


def _get_polynomial_from_binary_polynomial_index_list(polynomial_index_list, R):
    if polynomial_index_list == []:
        return R(1)
    p = 0
    x = R.gens()
    for _ in polynomial_index_list:
        m = 1
        for i in _:
            m = m * x[i]
        p += m
    return p


def _get_polynomial_from_word_polynomial_index_list(polynomial_index_list, R):
    if polynomial_index_list == []:
        return R(1)
    p = 0
    x = R.gens()
    y = R.construction()[1].gen()

    for _ in polynomial_index_list:
        m = 0  # presently it is for field of characteristic 2 only
        cc = "{0:b}".format(_[0])
        for i in range(len(cc)):
            if cc[i] == '1':  m = m + pow(y, len(cc) - 1 - i)
        for i in _[1]:
            m = m * x[i]
        p += m
    return p


def _bits_to_words_array(input, bits_inside_word, word_gf):
    y = word_gf.gen()

    monomials = [pow(y, i) for i in range(bits_inside_word - 1, -1, -1)]
    word_array = [0 for _ in
                  range(int(len(input) / bits_inside_word))]

    for i in range(len(word_array)):
        c = 0
        for j in range(len(monomials)):
            c += (input[(i * bits_inside_word) + j]) * monomials[j]
        word_array[i] = c

    return word_array

def _words_array_to_bits(word_array, word_gf):
    bits_inside_word = word_gf.degree()
    output = [0] * (len(word_array)*bits_inside_word)
    for i in range(len(word_array)):
        coeffcients = word_array[i].coefficients()
        monomials = word_array[i].monomials()
        for j in range(len(coeffcients)):
            bits = coeffcients[j].polynomial().monomials()
            for b in bits:
                output[i*bits_inside_word+(bits_inside_word-b.degree()-1)] += monomials[j]

    return output

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
        Return a list of polynomials for the feedback shift registers.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.stream_ciphers.a5_1_stream_cipher import A51StreamCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: a51 = A51StreamCipher()
            sage: fsr_component = a51.get_component_from_id("fsr_1_0")
            sage: algebraic = AlgebraicModel(a51)
            sage: L = fsr_component.algebraic_polynomials(algebraic)
            sage: L[0]
            linear_layer_0_6_y0 + linear_layer_0_6_x23 + linear_layer_0_6_x19 + linear_layer_0_6_x18 + linear_layer_0_6_x16 + linear_layer_0_6_x15 + linear_layer_0_6_x14 + linear_layer_0_6_x12 + linear_layer_0_6_x9 + linear_layer_0_6_x8 + linear_layer_0_6_x6 + linear_layer_0_6_x3
        """

        bits_inside_word = self.description[1]
        if bits_inside_word == 1:
            return self._algebraic_polynomials_binary(model)
        else:
            return self._algebraic_polynomials_word(model)

    def _algebraic_polynomials_binary(self, model):
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_R = model.ring()
        x_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        x_polynomial_ring = PolynomialRing(ring_R.base(), x_vars)
        x = vector(ring_R, (map(ring_R, [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)])))
        y = vector(ring_R, (map(ring_R, [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)])))
        number_of_registers = len(self.description[0])
        registers_polynomial = [0 for _ in range(number_of_registers)]
        registers_start = [0 for _ in range(number_of_registers)]
        registers_update_bit = [0 for _ in range(number_of_registers)]
        clock_polynomials = [None for _ in range(number_of_registers)]
        if len(self.description) > 2:
            clocks = self.description[2]
        else:
            clocks = 1

        end = 0
        for i in range(number_of_registers):
            registers_polynomial[i] = _get_polynomial_from_binary_polynomial_index_list(self.description[0][i][1], x_polynomial_ring)
            registers_start[i] = end
            end += self.description[0][i][0]
            registers_update_bit[i] = end-1
            if len(self.description[0][i]) > 2:
                clock_polynomials[i] = _get_polynomial_from_binary_polynomial_index_list(self.description[0][i][2], x_polynomial_ring)

        for _ in range(clocks):
            for i in range(number_of_registers):
                output_bit = registers_polynomial[i](*x)
                clock_bit = clock_polynomials[i](*x)
                for k in range(registers_start[i], registers_update_bit[i]):
                    x[k] = clock_bit*x[k+1] + (clock_bit+1)*x[k]
                x[registers_update_bit[i]] = clock_bit*output_bit + (clock_bit+1)*x[registers_update_bit[i]]

        output_polynomials = y+vector(x)
        return output_polynomials

    def _algebraic_polynomials_word(self, model):
        bits_inside_word = self.description[1]
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_R = model.ring()
        number_of_words = int(ninputs / bits_inside_word)

        x = vector(ring_R, (map(ring_R, [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)])))
        y = vector(ring_R, (map(ring_R, [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)])))
        word_gf = GF(pow(2, bits_inside_word))
        word_array = _bits_to_words_array(x, bits_inside_word, word_gf)
        word_polynomial_ring = PolynomialRing(word_gf, number_of_words, 'w')

        number_of_registers = len(self.description[0])
        registers_polynomial = [0 for _ in range(number_of_registers)]
        registers_start = [0 for _ in range(number_of_registers)]
        registers_update_word = [0 for _ in range(number_of_registers)]
        if len(self.description) > 2:
            clocks = self.description[2]
        else:
            clocks = 1

        end = 0
        for i in range(number_of_registers):
            registers_polynomial[i] = _get_polynomial_from_word_polynomial_index_list(self.description[0][i][1], word_polynomial_ring)
            registers_start[i] = end
            end += self.description[0][i][0]
            registers_update_word[i] = end - 1

        for _ in range(clocks):
            for i in range(number_of_registers):
                output_word = registers_polynomial[i](*word_array)
                for k in range(registers_start[i], registers_update_word[i]):
                    word_array[k] = word_array[k+1]
                word_array[registers_update_word[i]] = output_word

        x = _words_array_to_bits(word_array, word_gf)
        output_polynomials = y+vector(x)
        return output_polynomials

    def get_bit_based_vectorized_python_code(self, params):
        if len(self.description) > 2:
            clocks = self.description[2]
        else:
            clocks = 1
        if self.description[1] == 1:
            return [f'  {self.id} = bit_vector_fsr_binary([{",".join(params)} ], {self.description[0]}, {clocks})']
        else:
            return [f'  {self.id} = bit_vector_fsr_word([{",".join(params)} ], {self.description[0]}, {self.description[1]}, {clocks})']


    def get_byte_based_vectorized_python_code(self, params):
        if len(self.description) > 2:
            clocks = self.description[2]
        else:
            clocks = 1
        if self.description[1] == 1:
            return [f'  {self.id} = byte_vector_fsr_binary({params}, {self.description[0]}, {clocks})']
        else:
            return [f'  {self.id} = byte_vector_fsr_word({params}, {self.description[0]}, {self.description[1]}, {clocks})']
