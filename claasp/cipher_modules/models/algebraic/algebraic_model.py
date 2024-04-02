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


from sage.structure.sequence import Sequence
from sage.rings.polynomial.pbori.pbori import BooleanPolynomialRing


class AlgebraicModel:

    def __init__(self, cipher):
        self._cipher = cipher
        self.input_postfix = "x"
        self.output_postfix = "y"
        self._ring = None

    def connection_polynomials(self):
        """
        Return a list of polynomials that connects system of equations from each component.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: connection = AlgebraicModel(fancy).connection_polynomials()
            sage: connection[:24]
            [plaintext_y0 + sbox_0_0_x0,
             plaintext_y1 + sbox_0_0_x1,
             plaintext_y2 + sbox_0_0_x2,
             ...
             plaintext_y21 + sbox_0_5_x1,
             plaintext_y22 + sbox_0_5_x2,
             plaintext_y23 + sbox_0_5_x3]
        """
        return sum([self.connection_polynomials_at_round(r) for r in range(self._cipher.number_of_rounds)], [])

    def connection_polynomials_at_round(self, r):
        """
        Return a list of connection polynomials at round `r`.

        INPUT:

        - ``r`` -- **integer**

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: connection = AlgebraicModel(fancy).connection_polynomials_at_round(0)
            sage: connection[:24]
            [plaintext_y0 + sbox_0_0_x0,
             plaintext_y1 + sbox_0_0_x1,
             plaintext_y2 + sbox_0_0_x2,
             ...
             plaintext_y21 + sbox_0_5_x1,
             plaintext_y22 + sbox_0_5_x2,
             plaintext_y23 + sbox_0_5_x3]
        """
        polynomials = []

        for component in self._cipher.get_components_in_round(r):
            if component.type == "constant":
                continue
            input_vars, prev_input_vars = self._input_vars_previous_input_vars(component)
            polynomials += [x + y for (x, y) in zip(input_vars, prev_input_vars)]

        return polynomials

    def is_algebraically_secure(self, timeout):
        """
        Return `True` if the cipher is resistant against algebraic attack.

        INPUT:

        - ``timeout`` -- **integer**; the timeout for the Groebner basis computation in seconds

        EXAMPLES::

            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
            sage: toyspn = ToySPN1()
            sage: algebraic = AlgebraicModel(toyspn)
            sage: algebraic.is_algebraically_secure(30)
            False
        """
        from cysignals.alarm import alarm, cancel_alarm

        try:
            alarm(timeout)
            self.polynomial_system().groebner_basis()
            cancel_alarm()
            result = False
        except InterruptedError:
            result = True

        return result

    def nvars(self):
        """
        Return the number of variables.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: AlgebraicModel(fancy).nvars()
            96
        """
        nvars = 0
        for cipher_round in self._cipher.rounds_as_list:
            for component in cipher_round.components:
                if component.type == "sbox" or component.type == "linear_layer":
                    nvars += component.input_bit_size + component.output_bit_size

        return nvars

    def polynomial_system(self):
        """
        Return a polynomial system for the cipher.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: toyspn = ToySPN1()
            sage: AlgebraicModel(toyspn).polynomial_system()
            Polynomial Sequence with 80 Polynomials in 48 Variables

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: AlgebraicModel(fancy).polynomial_system()
            Polynomial Sequence with 228 Polynomials in 144 Variables

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: AlgebraicModel(speck).polynomial_system()
            Polynomial Sequence with 288 Polynomials in 352 Variables

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: aes = AESBlockCipher(word_size=4, state_size=2, number_of_rounds=1)
            sage: AlgebraicModel(aes).polynomial_system()
            Polynomial Sequence with 198 Polynomials in 128 Variables

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: tea = TeaBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=1)
            sage: AlgebraicModel(tea).polynomial_system()
            Polynomial Sequence with 352 Polynomials in 448 Variables

        """
        polynomials = []
        constant_vars = {}
        for r in range(self._cipher.number_of_rounds):
            polynomials += self.polynomial_system_at_round(r, True)
            constant_vars.update(self._dict_constant_component_polynomials(r))
            if constant_vars is not None:
                polynomials = self._remove_constant_polynomials(constant_vars, polynomials)

        return Sequence(polynomials)

    def polynomial_system_at_round(self, r, fun_call_flag=False):
        """
        Return a polynomial system at round `r`.

        INPUT:

        - ``r`` -- **integer**; round index

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: AlgebraicModel(fancy).polynomial_system_at_round(0)
            Polynomial Sequence with 228 Polynomials in 144 Variables
        """
        if not 0 <= r < self._cipher.number_of_rounds:
            raise ValueError(f"r must be in the range 0 <= r < {self._cipher.number_of_rounds}")

        polynomials = []

        for component in self._cipher.get_components_in_round(r):
            component_type = component.type
            operation = component.description[0]
            component_types = ["sbox", "linear_layer", "mix_column", "constant"]
            operations = ["XOR", "AND", "OR", "SHIFT", "ROTATE", "NOT", "MODADD", "MODSUB"]

            if component_type in component_types or (component_type == "word_operation" and operation in operations):
                polynomials += component.algebraic_polynomials(self)

            elif component_type == "word_operation" and \
                    operation in ['ROTATE_BY_VARIABLE_AMOUNT', 'SHIFT_BY_VARIABLE_AMOUNT']:
                raise ValueError(f"polynomial generation of {operation} operation is not supported at present")

        polynomials = self._apply_connection_variable_mapping(Sequence(polynomials), r)

        if fun_call_flag is False:
            constant_vars = self._dict_constant_component_polynomials(r)
            if constant_vars is not None:
                polynomials = self._remove_constant_polynomials(constant_vars, polynomials)

        return Sequence(polynomials)

    def _apply_connection_variable_mapping(self, polys, r):

        if not polys:
            return polys

        variable_substitution_dict = {}

        for component in self._cipher.get_components_in_round(r):
            if component.type == "constant":
                continue
            input_vars, prev_input_vars = self._input_vars_previous_input_vars(component)
            if component.type != "cipher_output":
                variable_substitution_dict.update({x: y for x, y in zip(input_vars, prev_input_vars)})
            else:
                variable_substitution_dict.update({y: x for x, y in zip(input_vars, prev_input_vars)})

            polys = polys.subs(variable_substitution_dict)

        return polys

    def _input_vars_previous_input_vars(self, component):
        input_vars = [component.id + "_" + self.input_postfix + str(i) for i in range(component.input_bit_size)]
        input_vars = list(map(self.ring(), input_vars))
        input_links = component.input_id_links
        input_positions = component.input_bit_positions

        prev_input_vars = []
        for k in range(len(input_links)):
            prev_input_vars += [input_links[k] + "_" + self.output_postfix + str(i) for i in
                                input_positions[k]]
        prev_input_vars = list(map(self.ring(), prev_input_vars))
        return input_vars, prev_input_vars

    def _dict_constant_component_polynomials(self, round_number):

        constant_vars = {}
        for component in self._cipher.get_components_in_round(round_number):
            if component.type == "constant":
                output_vars = [component.id + "_" + self.output_postfix + str(i) for i in
                               range(component.output_bit_size)]
            else:
                continue
            output_vars = list(map(self.ring(), output_vars))
            constant = int(component.description[0], 16)
            b = list(map(int, reversed(bin(constant)[2:])))
            b += [0] * (component.output_bit_size - len(b))
            constant_vars.update({x: y for x, y in zip(output_vars, b)})
        return constant_vars

    def _remove_constant_polynomials(self, constant_vars, polys):

        polys = Sequence(polys).subs(constant_vars)
        polys = [p for p in polys if p != 0]
        return polys

    def ring(self):
        """
        Return the polynomial ring for the system of equations.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: from claasp.cipher_modules.models.algebraic.boolean_polynomial_ring import is_boolean_polynomial_ring
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: ring = AlgebraicModel(fancy).ring()
            sage: is_boolean_polynomial_ring(ring)
            True

            sage: ring.ngens()
            432
        """
        if self._ring is not None:
            return self._ring

        names = self.var_names()
        self._ring = BooleanPolynomialRing(len(names), names, order="degneglex")

        return self._ring

    def var_names(self):
        """
        Return a list of variable names in the polynomial ring.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: var_names = AlgebraicModel(fancy).var_names()
            sage: var_names[0]
            'sbox_0_0_x0'
        """
        var_names = []

        for component in self._cipher.get_all_components():
            component_id = component.id
            input_size = component.input_bit_size
            output_size = component.output_bit_size

            if component.type != "constant":
                var_names += [component_id + "_" + self.input_postfix + str(i) for i in range(input_size)]
            var_names += [component_id + "_" + self.output_postfix + str(i) for i in range(output_size)]

            if component.type == "word_operation" and component.description[0].lower() == "modadd":
                ninput_words = component.description[1]
                nadditions = ninput_words - 1

                for n in range(nadditions):
                    # carry variables
                    var_names += [component_id + "_" + "c" + str(n) + "_" + str(i) for i in range(output_size)]
                    if n < nadditions - 1:
                        # aux output variables
                        var_names += \
                            [component_id + "_" + "o" + str(n) + "_" + str(i) for i in range(output_size)]
            elif component.type == "word_operation" and component.description[0].lower() == "modsub":
                ninput_words = component.description[1]
                nadditions = ninput_words - 1

                for n in range(nadditions):
                    # borrow variables
                    var_names += [component_id + "_" + "b" + str(n) + "_" + str(i) for i in range(output_size)]
                    if n < nadditions - 1:
                        # aux output variables
                        var_names += \
                            [component_id + "_" + "o" + str(n) + "_" + str(i) for i in range(output_size)]

        for i in range(len(self._cipher.inputs)):
            var_names += [self._cipher.inputs[i] + "_" +
                          self.output_postfix + str(j) for j in range(self._cipher.inputs_bit_size[i])]

        return var_names
