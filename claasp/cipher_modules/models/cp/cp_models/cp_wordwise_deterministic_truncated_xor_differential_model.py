
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


import os
import math
import itertools
import subprocess

from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel, solve_satisfy
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL)
from claasp.cipher_modules.models.cp.solvers import MODEL_DEFAULT_PATH, SOLVER_DEFAULT


class CpWordwiseDeterministicTruncatedXorDifferentialModel(CpDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher):
        super().__init__(cipher)

    def final_wordwise_deterministic_truncated_xor_differential_constraints(self, minimize=False):
        """
        Return a CP constraints list for the cipher outputs and solving indications for wordwise model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_wordwise_deterministic_truncated_xor_differential_model import CpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: cp = CpWordwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_wordwise_deterministic_truncated_xor_differential_constraints()
        """
        cipher_inputs = self._cipher.inputs
        cipher = self._cipher
        cp_constraints = []
        new_constraint = 'output['
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element}_active = \"++ show({element}_active) ++ \"\\n\" ++'
        for component_id in cipher.get_all_components_ids():
            new_constraint = new_constraint + \
                f'\"{component_id} = \"++ show({component_id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            if 'cipher_output' in component_id and minimize:
                cp_constraints.append(f'solve maximize count({self._cipher.get_all_components_ids()[-1]}_active, 0);')
        new_constraint = new_constraint[:-2] + '];'
        if cp_constraints == []:
            cp_constraints.append(solve_satisfy)
        cp_constraints.append(new_constraint)

        return cp_constraints

    def find_one_wordwise_deterministic_truncated_xor_differential_trail(self, number_of_rounds=None,
          
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds, wordwise=True)

        return self.solve('deterministic_truncated_xor_differential_one_solution', solver_name, num_of_processors, timelimit)

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self):
        
        cp_constraints = []
        cp_declarations = []
        for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            cp_declarations.append(f'array[0..{bit_size // self.word_size - 1}] of var 0..3: {input_}_active;')
            cp_declarations.append(
                f'array[0..{bit_size // self.word_size - 1}] of var -2..{2 ** self.word_size - 1}: {input_}_value;')
            for i in range(bit_size // self.word_size):
                cp_constraints.append(f'constraint if {input_}_active[{i}] == 0 then {input_}_value[{i}] = 0 elseif '
                                      f'{input_}_active[{i}] == 1 then {input_}_value[{i}] > 0 elseif '
                                      f'{input_}_active[{i}] == 2 then {input_}_value[{i}] =-1 else '
                                      f'{input_}_value[{i}] =-2 endif;')
        for component in self._cipher.get_all_components():
            if CONSTANT not in component.type:
                output_id_link = component.id
                output_size = int(component.output_bit_size)
                cp_declarations.append(
                    f'array[0..{output_size // self.word_size - 1}] of var 0..3: {output_id_link}_active;')
                cp_declarations.append(
                    f'array[0..{output_size // self.word_size - 1}] of var -2..{2 ** self.word_size - 1}: '
                    f'{output_id_link}_value;')
                for i in range(output_size // self.word_size):
                    cp_constraints.append(
                        f'constraint if {output_id_link}_active[{i}] == 0 then {output_id_link}_value[{i}] = 0 elseif '
                        f'{output_id_link}_active[{i}] == 1 then {output_id_link}_value[{i}] > 0 elseif '
                        f'{output_id_link}_active[{i}] == 2 then {output_id_link}_value[{i}] =-1 else '
                        f'{output_id_link}_value[{i}] =-2 endif;')
                if CIPHER_OUTPUT in component.type:
                    cp_constraints.append(f'constraint count({output_id_link}_active,2) < {output_size};')
        cp_constraints.append('constraint count(plaintext_active,1) > 0;')

        return cp_declarations, cp_constraints

