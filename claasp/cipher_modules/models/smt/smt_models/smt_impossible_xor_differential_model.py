
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

"""
The search methods presented in this class differ from those of the classes
:py:class:`Smt Bitwise Impossible Xor Differential Model
<cipher_modules.models.smt.smt_models.smt_bitwise_impossible_xor_differential_cipher_model>`

and :py:class:`Smt Wordwise Impossible Xor Differential Model
<cipher_modules.models.smt.smt_models.smt_wordwise_impossible_xor_differential_cipher_model>`.

Indeed, this class implements the framework proposed by `Cui et al.<https://eprint.iacr.org/2016/689.pdf>` which uses
infeasibility of a XOR DIFFERENTIAL model to detect an impossible differential trail.
"""

from itertools import combinations, product

import numpy as np

from claasp.cipher_modules.models.smt import solvers
from claasp.cipher_modules.models.smt.smt_models.smt_xor_differential_model import SmtXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables, \
    convert_solver_solution_to_dictionary, set_components_variables_to_one, \
    _convert_impossible_xor_differential_solution_to_dictionnary
from claasp.name_mappings import (INPUT_PLAINTEXT, INPUT_KEY, IMPOSSIBLE_XOR_DIFFERENTIAL)


class SmtImpossibleXorDifferentialModel(SmtXorDifferentialModel):
    def __init__(self, cipher, counter='sequential'):
        super().__init__(cipher, counter)

    def find_one_impossible_xor_differential_trail(self, number_of_active_key_bits=1, number_of_active_pt_bits=1, number_of_active_ct_bits=1, solver_name=solvers.SOLVER_DEFAULT):
        """
        Returns one impossible XOR differential trail.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            # to retrieve one of the trails of Table 2 from https://eprint.iacr.org/2016/689
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: lblock = LBlockBlockCipher(number_of_rounds=16)
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_impossible_xor_differential_model import SmtImpossibleXorDifferentialModel
            sage: smt = SmtImpossibleXorDifferentialModel(lblock)
            sage: trail = smt.find_one_impossible_xor_differential_trail(1,0,0) # doctest: +SKIP
            ...

        """

        return self._enumerate_impossible_xor_differential_trails(number_of_active_key_bits, number_of_active_pt_bits,
                                                                  number_of_active_ct_bits, solver_name,
                                                                  output_only_one_solution=True)

    def find_all_impossible_xor_differential_trails(self, number_of_active_key_bits=1, number_of_active_pt_bits=1, number_of_active_ct_bits=1, solver_name=solvers.SOLVER_DEFAULT):
        """
        Returns all impossible XOR differential trails.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            # to retrieve the trails of Table 2 from https://eprint.iacr.org/2016/689
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: lblock = LBlockBlockCipher(number_of_rounds=16)
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_impossible_xor_differential_model import SmtImpossibleXorDifferentialModel
            sage: smt = SmtImpossibleXorDifferentialModel(lblock)
            sage: trails = smt.find_all_impossible_xor_differential_trails(1,0,0) # doctest: +SKIP
            ...

        """

        return self._enumerate_impossible_xor_differential_trails(number_of_active_key_bits, number_of_active_pt_bits,
                                                                  number_of_active_ct_bits, solver_name)

    def _enumerate_impossible_xor_differential_trails(self, number_of_active_key_bits, number_of_active_pt_bits, number_of_active_ct_bits, solver_name=solvers.SOLVER_DEFAULT, output_only_one_solution=False):

        pt_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_PLAINTEXT)]
        key_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_KEY)]
        ct_id = [c.id for c in self._cipher.get_all_components() if c.type == 'cipher_output'][0]

        key_combinations = combinations(range(key_size), number_of_active_key_bits)
        pt_combinations = combinations(range(pt_size), number_of_active_pt_bits)
        ct_combinations = combinations(range(self._cipher.output_bit_size), number_of_active_ct_bits)

        solutions_list = []
        solving_time = 0

        for key_bits, pt_bits, ct_bits in product(key_combinations, pt_combinations, ct_combinations):
            key_vars = set_components_variables_to_one(INPUT_KEY, key_size, list(key_bits))
            pt_vars = set_components_variables_to_one(INPUT_PLAINTEXT, pt_size, list(pt_bits))
            ct_vars = set_components_variables_to_one(ct_id, self._cipher.output_bit_size, list(ct_bits))

            trail = self.find_one_xor_differential_trail(fixed_values=[key_vars, pt_vars, ct_vars],
                                                         solver_name=solver_name)

            solving_time += trail['solving_time_seconds']

            if trail['status'] == 'UNSATISFIABLE':
                solution = _convert_impossible_xor_differential_solution_to_dictionnary(trail, solving_time,
                                                                                        [key_vars, pt_vars, ct_vars])
                if output_only_one_solution:
                    return solution
                solutions_list.append(solution)

        return solutions_list

