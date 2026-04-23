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
from claasp.component import Component
from claasp.cipher_modules.generic_functions import _bits_to_words_array


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
        cc = f"{_[0]:b}"
        for i in range(len(cc)):
            if cc[i] == "1":
                m = m + pow(y, len(cc) - 1 - i)
        for i in _[1]:
            m = m * x[i]
        p += m
    return p


def _words_array_to_bits(word_array, word_gf):
    bits_inside_word = word_gf.degree()
    output = [0] * (len(word_array) * bits_inside_word)
    for i in range(len(word_array)):
        coeffcients = word_array[i].coefficients()
        monomials = word_array[i].monomials()
        for j in range(len(coeffcients)):
            bits = coeffcients[j].polynomial().monomials()
            for b in bits:
                output[i * bits_inside_word + (bits_inside_word - b.degree() - 1)] += monomials[j]

    return output


class Fsr(Component):
    """
    Construct an FSR component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``description`` -- **list**; component-specific metadata used by the implementation.

    EXAMPLES::

        sage: from claasp.components.fsr_component import Fsr
        sage: fsr_description = [[[[5, [[4], [5], [6, 7]]], [7, [[0], [8], [1, 2]]]], 1]]
        sage: component = Fsr(0, 0, ['input'], [[0, 1, 2, 3, 4, 5, 6, 7, 8]], 0, fsr_description)
        sage: print(component.id)
        fsr_0_0
        sage: print(component.type)
        fsr
        sage: print(component.output_bit_size)
        0
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        description,
    ):
        component_id = f"fsr_{current_round_number}_{current_round_number_of_components}"
        component_type = "fsr"
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

            sage: from claasp.ciphers.single_component_ciphers.fsr_cipher import FsrCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: binary_cipher = FsrCipher(register_size=4)
            sage: fsr_component = binary_cipher.get_component_from_id("fsr_0_0")
            sage: algebraic = AlgebraicModel(binary_cipher)
            sage: binary = fsr_component.algebraic_polynomials(algebraic)
            sage: [str(p) for p in binary]
            ['fsr_0_0_y0 + fsr_0_0_x1', 'fsr_0_0_y1 + fsr_0_0_x2', 'fsr_0_0_y2 + fsr_0_0_x3', 'fsr_0_0_y3 + fsr_0_0_x1 + fsr_0_0_x0']

            sage: clocked_cipher = FsrCipher(register_size=4, description=[[[4, [[0], [1]], [[0]]]], 1])
            sage: fsr_component = clocked_cipher.get_component_from_id("fsr_0_0")
            sage: algebraic = AlgebraicModel(clocked_cipher)
            sage: clocked = fsr_component.algebraic_polynomials(algebraic)
            sage: [str(p) for p in clocked]
            ['fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y0', 'fsr_0_0_x0*fsr_0_0_x2 + fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y1 + fsr_0_0_x1', 'fsr_0_0_x0*fsr_0_0_x3 + fsr_0_0_x0*fsr_0_0_x2 + fsr_0_0_y2 + fsr_0_0_x2', 'fsr_0_0_x0*fsr_0_0_x3 + fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y3 + fsr_0_0_x3 + fsr_0_0_x0']

            sage: word_cipher = FsrCipher(register_size=4, description=[[[2, [[1, [0]], [1, [1]]]]], 2])
            sage: fsr_component = word_cipher.get_component_from_id("fsr_0_0")
            sage: algebraic = AlgebraicModel(word_cipher)
            sage: word = fsr_component.algebraic_polynomials(algebraic)
            sage: [str(p) for p in word]
            ['fsr_0_0_y0 + fsr_0_0_x2', 'fsr_0_0_y1 + fsr_0_0_x3', 'fsr_0_0_y2 + fsr_0_0_x2 + fsr_0_0_x0', 'fsr_0_0_y3 + fsr_0_0_x3 + fsr_0_0_x1']
        """
        bits_inside_word = self.description[1]
        if bits_inside_word == 1:
            return self._algebraic_polynomials_binary(model)
        return self._algebraic_polynomials_word(model)

    def _algebraic_polynomials_binary(self, model):
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_R = model.ring()
        x_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        x_polynomial_ring = PolynomialRing(ring_R.base(), x_vars)
        x = vector(ring_R, (map(ring_R, [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)])))
        y = vector(ring_R, (map(ring_R, [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)])))
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
            registers_polynomial[i] = _get_polynomial_from_binary_polynomial_index_list(
                self.description[0][i][1], x_polynomial_ring
            )
            registers_start[i] = end
            end += self.description[0][i][0]
            registers_update_bit[i] = end - 1
            if len(self.description[0][i]) > 2:
                clock_polynomials[i] = _get_polynomial_from_binary_polynomial_index_list(
                    self.description[0][i][2], x_polynomial_ring
                )

        for _ in range(clocks):
            for i in range(number_of_registers):
                feedback_bit = registers_polynomial[i](*x)
                if clock_polynomials[i] is not None:
                    clock_bit = clock_polynomials[i](*x)
                    for k in range(registers_start[i], registers_update_bit[i]):
                        x[k] = clock_bit * x[k + 1] + (clock_bit + 1) * x[k]
                    x[registers_update_bit[i]] = clock_bit * feedback_bit + (clock_bit + 1) * x[registers_update_bit[i]]
                else:
                    for k in range(registers_start[i], registers_update_bit[i]):
                        x[k] = x[k + 1]
                    x[registers_update_bit[i]] = feedback_bit

        output_polynomials = y + vector(x)
        return output_polynomials

    def _algebraic_polynomials_word(self, model):
        bits_inside_word = self.description[1]
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size

        word_gf = GF(2**bits_inside_word)  # Finite field 2^bits_inside_word
        x_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        y_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        ring_R = PolynomialRing(word_gf, x_vars + y_vars)  # Now the base ring is GF(2^n)

        number_of_words = int(ninputs / bits_inside_word)

        x = vector(ring_R, (map(ring_R, [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)])))
        y = vector(ring_R, (map(ring_R, [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)])))

        word_array = _bits_to_words_array(x, bits_inside_word, word_gf)
        word_polynomial_ring = PolynomialRing(word_gf, number_of_words, "w")

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
            registers_polynomial[i] = _get_polynomial_from_word_polynomial_index_list(
                self.description[0][i][1], word_polynomial_ring
            )
            registers_start[i] = end
            end += self.description[0][i][0]
            registers_update_word[i] = end - 1

        for _ in range(clocks):
            for i in range(number_of_registers):
                output_word = registers_polynomial[i](*word_array)
                for k in range(registers_start[i], registers_update_word[i]):
                    word_array[k] = word_array[k + 1]
                word_array[registers_update_word[i]] = output_word

        x = _words_array_to_bits(word_array, word_gf)
        output_polynomials = y + vector(x)
        ring_R = model.ring()

        output_polynomials_gf2 = [ring_R(str(p)) for p in output_polynomials]
        return output_polynomials_gf2
