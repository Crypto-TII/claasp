
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

from claasp.cipher_modules.models.cp.mzn_models.mzn_bitwise_deterministic_truncated_xor_differential_model import MznBitwiseDeterministicTruncatedXorDifferentialModel, solve_satisfy
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL)
from claasp.cipher_modules.models.cp.solvers import MODEL_DEFAULT_PATH, SOLVER_DEFAULT


class MznWordwiseDeterministicTruncatedXorDifferentialModel(MznBitwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher):
        super().__init__(cipher)

    def final_wordwise_deterministic_truncated_xor_differential_constraints(self, minimize=False):
        """
        Return a CP constraints list for the cipher outputs and solving indications for wordwise model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_wordwise_deterministic_truncated_xor_differential_model import MznWordwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: cp = MznWordwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_wordwise_deterministic_truncated_xor_differential_constraints()
            ['solve satisfy;',
             'output["plaintext_active = "++ show(plaintext_active) ++ "\\n" ++"key_active = "++ show(key_active) ++ "\\n" ++"rot_0_0 = "++ show(rot_0_0_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_0_1 = "++ show(modadd_0_1_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_0_2 = "++ show(xor_0_2_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_0_3 = "++ show(rot_0_3_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_0_4 = "++ show(xor_0_4_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_0_5 = "++ show(intermediate_output_0_5_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_0_6 = "++ show(intermediate_output_0_6_active)++ "\\n" ++ "0" ++ "\\n" ++"constant_1_0 = "++ show(constant_1_0_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_1_1 = "++ show(rot_1_1_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_1_2 = "++ show(modadd_1_2_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_1_3 = "++ show(xor_1_3_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_1_4 = "++ show(rot_1_4_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_1_5 = "++ show(xor_1_5_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_1_6 = "++ show(rot_1_6_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_1_7 = "++ show(modadd_1_7_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_1_8 = "++ show(xor_1_8_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_1_9 = "++ show(rot_1_9_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_1_10 = "++ show(xor_1_10_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_11 = "++ show(intermediate_output_1_11_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_12 = "++ show(intermediate_output_1_12_active)++ "\\n" ++ "0" ++ "\\n" ++"constant_2_0 = "++ show(constant_2_0_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_2_1 = "++ show(rot_2_1_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_2_2 = "++ show(modadd_2_2_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_2_3 = "++ show(xor_2_3_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_2_4 = "++ show(rot_2_4_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_2_5 = "++ show(xor_2_5_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_2_6 = "++ show(rot_2_6_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_2_7 = "++ show(modadd_2_7_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_2_8 = "++ show(xor_2_8_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_2_9 = "++ show(rot_2_9_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_2_10 = "++ show(xor_2_10_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_2_11 = "++ show(intermediate_output_2_11_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_2_12 = "++ show(intermediate_output_2_12_active)++ "\\n" ++ "0" ++ "\\n" ++"constant_3_0 = "++ show(constant_3_0_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_3_1 = "++ show(rot_3_1_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_3_2 = "++ show(modadd_3_2_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_3_3 = "++ show(xor_3_3_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_3_4 = "++ show(rot_3_4_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_3_5 = "++ show(xor_3_5_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_3_6 = "++ show(rot_3_6_active)++ "\\n" ++ "0" ++ "\\n" ++"modadd_3_7 = "++ show(modadd_3_7_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_3_8 = "++ show(xor_3_8_active)++ "\\n" ++ "0" ++ "\\n" ++"rot_3_9 = "++ show(rot_3_9_active)++ "\\n" ++ "0" ++ "\\n" ++"xor_3_10 = "++ show(xor_3_10_active)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_3_11 = "++ show(intermediate_output_3_11_active)++ "\\n" ++ "0" ++ "\\n" ++"cipher_output_3_12 = "++ show(cipher_output_3_12_active)++ "\\n" ++ "0" ++ "\\n" ];']
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
                                                                fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = False):
          
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds, wordwise=True)

        if solve_with_API:
            return self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        return self.solve('deterministic_truncated_xor_differential_one_solution', solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)

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

