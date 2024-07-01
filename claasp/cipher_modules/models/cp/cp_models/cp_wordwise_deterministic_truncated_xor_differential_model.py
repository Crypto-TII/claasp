
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
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_deterministic_truncated_xor_differential_constraints()[:-1]
            ['solve satisfy;']
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
                                                                fixed_values=[], solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `Chuffed`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=1)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(
            ....:         component_id='plaintext',
            ....:         constraint_type='not_equal',
            ....:         bit_positions=range(32),
            ....:         bit_values=[0]*32)
            sage: key = set_fixed_variables(
            ....:         component_id='key',
            ....:         constraint_type='equal',
            ....:         bit_positions=range(64),
            ....:         bit_values=[0]*64)
            sage: cp.find_one_deterministic_truncated_xor_differential_trail(1, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r1',
              'components_values': {'cipher_output_0_6': {'value': '22222222222222212222222222222220',
                'weight': 0},
               'intermediate_output_0_5': {'value': '0000000000000000', 'weight': 0},
               'key': {'value': '0000000000000000000000000000000000000000000000000000000000000000',
                'weight': 0},
               'modadd_0_1': {'value': '2222222222222221', 'weight': 0},
               'plaintext': {'value': '11111111011111111111111111111111', 'weight': 0},
               'rot_0_0': {'value': '1111111111111110', 'weight': 0},
               'rot_0_3': {'value': '1111111111111111', 'weight': 0},
               'xor_0_2': {'value': '2222222222222221', 'weight': 0},
               'xor_0_4': {'value': '2222222222222220', 'weight': 0}},
              'memory_megabytes': 0.01,
              'model_type': 'deterministic_truncated_xor_differential_one_solution',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.0,
              'total_weight': '0.0'}]
        """
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        self.build_deterministic_truncated_xor_differential_trail_model(fixed_values, number_of_rounds, wordwise=True)

        return self.solve('deterministic_truncated_xor_differential_one_solution', solver_name, num_of_processors, timelimit)

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of CP constraints for the inputs of the cipher for truncated deterministic xor differential model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: aes = AESBlockCipher(number_of_rounds = 2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(aes)
            sage: cp.input_wordwise_deterministic_truncated_xor_differential_constraints()
            (['array[0..15] of var 0..3: key_active;',
              'array[0..15] of var -2..255: key_value;',
               ...
              'array[0..15] of var -2..255: cipher_output_1_32_value;'],
             ['constraint if key_active[0] == 0 then key_value[0] = 0 elseif key_active[0] == 1 then key_value[0] > 0 elseif key_active[0] == 2 then key_value[0] =-1 else key_value[0] =-2 endif;',
               ...
              'constraint if cipher_output_1_32_active[15] == 0 then cipher_output_1_32_value[15] = 0 elseif cipher_output_1_32_active[15] == 1 then cipher_output_1_32_value[15] > 0 elseif cipher_output_1_32_active[15] == 2 then cipher_output_1_32_value[15] =-1 else cipher_output_1_32_value[15] =-2 endif;',
              'constraint count(cipher_output_1_32_active,2) < 128;',
              'constraint count(plaintext,1) > 0;',
              'constraint count(plaintext,2) = 0;'])
        """
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

