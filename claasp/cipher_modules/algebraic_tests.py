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


from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


class AlgebraicTests:

    """
        Construct an instance of Algebraic Tests of the cipher.

        EXAMPLES::

            sage: from claasp.cipher_modules.algebraic_tests import AlgebraicTests
            sage: from claasp.ciphers.toys.toyspn1 import ToySPN1
            sage: toyspn = ToySPN1(number_of_rounds=2)
            sage: alg_test = AlgebraicTests(toyspn)
            sage: alg_test.algebraic_tests(timeout_in_seconds=10)
            {'input_parameters': {'cipher': toyspn1_p6_k6_o6_r2,
              'timeout_in_seconds': 10,
              'test_name': 'algebraic_tests'},
             'test_results': {'number_of_variables': [24, 42],
              'number_of_equations': [34, 74],
              'number_of_monomials': [54, 102],
              'max_degree_of_equations': [2, 2],
              'test_passed': [False, False]}}

            sage: from claasp.cipher_modules.algebraic_tests import AlgebraicTests
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: alg_test = AlgebraicTests(speck)
            sage: alg_test.algebraic_tests(timeout_in_seconds=30)
            {'input_parameters': {'cipher': speck_p32_k64_o32_r1,
              'timeout_in_seconds': 30,
              'test_name': 'algebraic_tests'},
             'test_results': {'number_of_variables': [112],
              'number_of_equations': [64],
              'number_of_monomials': [157],
              'max_degree_of_equations': [2],
              'test_passed': [True]}}

    """

    def __init__(self, cipher):
        self._cipher = cipher
        self._algebraic_model = AlgebraicModel(cipher)

    def algebraic_tests(self, timeout_in_seconds=60):
        from sage.structure.sequence import Sequence
        nvars_up_to_round = []
        npolynomials_up_to_round = []
        nmonomials_up_to_round = []
        max_deg_of_equations_up_to_round = []
        tests_up_to_round = []

        F = []
        dict_vars = {}
        for round_number in range(self._cipher.number_of_rounds):
            F += self._algebraic_model.polynomial_system_at_round(round_number, True)
            dict_vars.update(self._algebraic_model._dict_const_rot_not_shift_component_polynomials(round_number))
            if round_number == self._cipher.number_of_rounds - 1 and dict_vars:
                dict_vars = self._algebraic_model._substitute_cipher_output_vars_dict_vars(dict_vars, round_number)
            if dict_vars:
                F = self._algebraic_model._eliminate_const_not_shift_rot_components_polynomials(dict_vars, F)

            Fseq = Sequence(F)
            nvars_up_to_round.append(Fseq.nvariables())
            npolynomials_up_to_round.append(len(Fseq))
            nmonomials_up_to_round.append(Fseq.nmonomials())
            max_deg_of_equations_up_to_round.append(Fseq.maximal_degree())

            from cysignals.alarm import alarm, cancel_alarm, AlarmInterrupt
            try:
                alarm(timeout_in_seconds)
                Fseq.groebner_basis()
                cancel_alarm()
                result = False
            except AlarmInterrupt:
                result = True

            tests_up_to_round.append(result)

        input_parameters = {
            "cipher": self._cipher,
            "timeout_in_seconds": timeout_in_seconds,
            "test_name": "algebraic_tests"
        }
        test_results = {
            "number_of_variables": nvars_up_to_round,
            "number_of_equations": npolynomials_up_to_round,
            "number_of_monomials": nmonomials_up_to_round,
            "max_degree_of_equations": max_deg_of_equations_up_to_round,
            "test_passed": tests_up_to_round
        }

        output = {
            "input_parameters": input_parameters,
            "test_results": test_results
        }

        return output
