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
            sage: alg_test.algebraic_tests(30) # timeout=30 seconds

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: alg_test = AlgebraicTests(speck)
            sage: alg_test.algebraic_tests(60) # timeout=60 seconds

            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: alg_test = AlgebraicTests(speck)
            sage: alg_test.algebraic_tests(60)
    """

    def __init__(self, cipher):
        self._cipher = cipher

    def algebraic_tests(self, timeout=60):
        from sage.structure.sequence import Sequence
        nvars_up_to_round = []

        npolynomials_up_to_round = []
        nmonomials_up_to_round = []
        max_deg_of_equations_up_to_round = []
        tests_up_to_round = []

        F = []

        algebraic_model = AlgebraicModel(self._cipher)
        for round_number in range(self._cipher.number_of_rounds):
            F += algebraic_model.polynomial_system_at_round(round_number) + \
                 algebraic_model.connection_polynomials_at_round(round_number)
            Fseq = Sequence(F)
            nvars_up_to_round.append(Fseq.nvariables())
            npolynomials_up_to_round.append(len(Fseq))
            nmonomials_up_to_round.append(Fseq.nmonomials())
            max_deg_of_equations_up_to_round.append(Fseq.maximal_degree())

            from cysignals.alarm import alarm, cancel_alarm, AlarmInterrupt
            try:
                alarm(timeout)
                Fseq.groebner_basis()
                cancel_alarm()
                result = False
            except AlarmInterrupt:
                result = True

            tests_up_to_round.append(result)

        input_parameters = {
            "timeout": timeout,
            "test_name": "algebraic_tests",
            "cipher": self._cipher
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
