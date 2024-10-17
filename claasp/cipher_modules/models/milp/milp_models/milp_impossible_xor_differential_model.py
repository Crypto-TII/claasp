
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
:py:class:`Milp Bitwise Impossible Xor Differential Model
<cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_cipher_model>`

and :py:class:`Milp Wordwise Impossible Xor Differential Model
<cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_cipher_model>`.

Indeed, this class implements the framework proposed by `Cui et al.<https://eprint.iacr.org/2016/689.pdf>` which uses
infeasibility of a XOR DIFFERENTIAL model to detect an impossible differential trail.
"""

from itertools import combinations, product

import numpy as np

from claasp.cipher_modules.models.milp import solvers
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables, \
    convert_solver_solution_to_dictionary
from claasp.name_mappings import (INPUT_PLAINTEXT, INPUT_KEY, IMPOSSIBLE_XOR_DIFFERENTIAL)


class MilpImpossibleXorDifferentialModel(MilpXorDifferentialModel):
    def __init__(self, cipher, counter='sequential', compact=False):
        super().__init__(cipher, counter, compact)

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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_impossible_xor_differential_model import MilpImpossibleXorDifferentialModel
            sage: milp = MilpImpossibleXorDifferentialModel(lblock)
            sage: trail = milp.find_one_impossible_xor_differential_trail(1,0,0) # doctest: +SKIP
            ...

        """

        pt_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_PLAINTEXT)]
        key_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_KEY)]
        ct_id = [c.id for c in self._cipher.get_all_components() if c.type == 'cipher_output'][0]

        key_combinations = combinations(range(key_size), number_of_active_key_bits)
        pt_combinations = combinations(range(pt_size), number_of_active_pt_bits)
        ct_combinations = combinations(range(self._cipher.output_bit_size), number_of_active_ct_bits)

        solving_time = 0

        for key_bits, pt_bits, ct_bits in product(key_combinations, pt_combinations, ct_combinations):
            key = np.zeros(key_size, dtype=int)
            key[list(key_bits)] = 1
            key_vars = set_fixed_variables(component_id=INPUT_KEY, constraint_type='equal', bit_positions=range(key_size), bit_values=key)

            pt = np.zeros(pt_size, dtype=int)
            pt[list(pt_bits)] = 1
            pt_vars = set_fixed_variables(component_id=INPUT_PLAINTEXT, constraint_type='equal',
                                           bit_positions=range(pt_size), bit_values=pt)

            ct = np.zeros(self._cipher.output_bit_size, dtype=int)
            ct[list(ct_bits)] = 1
            ct_vars = set_fixed_variables(component_id=ct_id, constraint_type='equal',
                                           bit_positions=range(self._cipher.output_bit_size), bit_values=ct)

            trail = self.find_one_xor_differential_trail(fixed_values=[key_vars, pt_vars, ct_vars],
                                                         solver_name=solver_name)

            solving_time += trail['solving_time_seconds']

            if trail['status'] == 'UNSATISFIABLE':
                for component in [INPUT_KEY, INPUT_PLAINTEXT, ct_id]:
                    trail['components_values'][component] = {}
                trail['solving_time_seconds'] == solving_time
                trail['components_values'][INPUT_KEY]['value'] = np.packbits(key).tobytes().hex()
                trail['components_values'][INPUT_PLAINTEXT]['value'] = np.packbits(pt).tobytes().hex()
                trail['components_values'][ct_id]['value'] = np.packbits(ct).tobytes().hex()
                trail['model_type'] = IMPOSSIBLE_XOR_DIFFERENTIAL
                trail['test_name'] = 'find_one_impossible_xor_differential_trail'
                trail['status'] = 'SATISFIABLE'
                return trail


        solution = convert_solver_solution_to_dictionary(self._cipher, IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name, solving_time,
                                                         None, [], None)
        return solution

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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_impossible_xor_differential_model import MilpImpossibleXorDifferentialModel
            sage: milp = MilpImpossibleXorDifferentialModel(lblock)
            sage: trails = milp.find_all_impossible_xor_differential_trails(1,0,0) # doctest: +SKIP
            ...

        """

        pt_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_PLAINTEXT)]
        key_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(INPUT_KEY)]
        ct_id = [c.id for c in self._cipher.get_all_components() if c.type == 'cipher_output'][0]

        key_combinations = combinations(range(key_size), number_of_active_key_bits)
        pt_combinations = combinations(range(pt_size), number_of_active_pt_bits)
        ct_combinations = combinations(range(self._cipher.output_bit_size), number_of_active_ct_bits)

        solutions_list = []
        solving_time = 0

        for key_bits, pt_bits, ct_bits in product(key_combinations, pt_combinations, ct_combinations):
            key = np.zeros(key_size, dtype=int)
            key[list(key_bits)] = 1
            key_vars = set_fixed_variables(component_id=INPUT_KEY, constraint_type='equal', bit_positions=range(key_size), bit_values=key)

            pt = np.zeros(pt_size, dtype=int)
            pt[list(pt_bits)] = 1
            pt_vars = set_fixed_variables(component_id=INPUT_PLAINTEXT, constraint_type='equal',
                                           bit_positions=range(pt_size), bit_values=pt)

            ct = np.zeros(self._cipher.output_bit_size, dtype=int)
            ct[list(ct_bits)] = 1
            ct_vars = set_fixed_variables(component_id=ct_id, constraint_type='equal',
                                           bit_positions=range(self._cipher.output_bit_size), bit_values=ct)

            trail = self.find_one_xor_differential_trail(fixed_values=[key_vars, pt_vars, ct_vars],
                                                         solver_name=solver_name)

            solving_time += trail['solving_time_seconds']

            if trail['status'] == 'UNSATISFIABLE':
                for component in [INPUT_KEY, INPUT_PLAINTEXT, ct_id]:
                    trail['components_values'][component] = {}
                trail['solving_time_seconds'] == solving_time
                trail['components_values'][INPUT_KEY]['value'] = np.packbits(key).tobytes().hex()
                trail['components_values'][INPUT_PLAINTEXT]['value'] = np.packbits(pt).tobytes().hex()
                trail['components_values'][ct_id]['value'] = np.packbits(ct).tobytes().hex()
                trail['model_type'] = IMPOSSIBLE_XOR_DIFFERENTIAL
                trail['test_name'] = 'find_one_impossible_xor_differential_trail'
                trail['status'] = 'SATISFIABLE'
                solutions_list.append(trail)

        return solutions_list
