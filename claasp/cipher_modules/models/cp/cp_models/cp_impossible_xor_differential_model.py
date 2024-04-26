
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

from claasp.cipher_modules.models.cp.cp_model import solve_satisfy
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary
from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel

from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, IMPOSSIBLE_XOR_DIFFERENTIAL)
from claasp.cipher_modules.models.cp.solvers import SOLVER_DEFAULT


class CpImpossibleXorDifferentialModel(CpDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher):
        super().__init__(cipher)
        self.inverse_cipher = cipher.cipher_inverse()
        self.middle_round = 1
        self.key_schedule_bits_distribution = {}
        self.key_involvements = self.get_state_key_bits_positions()
        self.inverse_key_involvements = self.get_inverse_state_key_bits_positions()
    
    def add_solution_to_components_values(self, component_id, component_solution, components_values, j, output_to_parse,
                                          solution_number, string):
        inverse_cipher = self.inverse_cipher
        if component_id in self._cipher.inputs:
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution
        elif component_id in self.inverse_cipher.inputs:
            components_values[f'solution{solution_number}'][f'inverse_{component_id}'] = component_solution
        elif f'{component_id}_i' in string:
            components_values[f'solution{solution_number}'][f'{component_id}_i'] = component_solution
        elif f'{component_id}_o' in string:
            components_values[f'solution{solution_number}'][f'{component_id}_o'] = component_solution
        elif f'inverse_{component_id} ' in string:
            components_values[f'solution{solution_number}'][f'inverse_{component_id}'] = component_solution
        elif f'{component_id} ' in string:
            components_values[f'solution{solution_number}'][f'{component_id}'] = component_solution
            
    def build_impossible_backward_model(self, backward_components, clean = True):
        inverse_variables = []
        inverse_constraints = []
        for component in backward_components:
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
            if component.type not in component_types or \
                    (component.type == WORD_OPERATION and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            if component.type == SBOX:
                variables, constraints, sbox_mant = component.cp_deterministic_truncated_xor_differential_trail_constraints(self.sbox_mant)
                self.sbox_mant = sbox_mant
            else:
                variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
            inverse_variables.extend(variables)
            inverse_constraints.extend(constraints)
        
        if clean:
            inverse_variables, inverse_constraints = self.clean_inverse_impossible_variables_constraints(backward_components, inverse_variables, inverse_constraints)
            
        return inverse_variables, inverse_constraints
    
    def build_impossible_forward_model(self, forward_components, clean = False):
        direct_variables = []
        direct_constraints = []
        for component in forward_components:
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER,
                               SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'OR', 'MODADD', 'MODSUB', 'NOT', 'ROTATE', 'SHIFT', 'XOR']
            if component.type not in component_types or \
                    (component.type == WORD_OPERATION and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            if component.type == SBOX:
                variables, constraints, sbox_mant = component.cp_deterministic_truncated_xor_differential_trail_constraints(self.sbox_mant)
                self.sbox_mant = sbox_mant
            else:
                variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
            direct_variables.extend(variables)
            direct_constraints.extend(constraints)
            
        if clean:
            direct_variables, direct_constraints = self.clean_inverse_impossible_variables_constraints(forward_components, direct_variables, direct_constraints)
            
        return direct_variables, direct_constraints
        
    '''        
    def build_impossible_attack_model(self, fixed_variables, number_of_rounds, initial_round, middle_round, final_round, intermediate_components):
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        inverse_cipher = self.inverse_cipher
        if final_round is None:
            final_round = self._cipher.number_of_rounds
        key_components, key_ids = self.extract_key_schedule()
        constant_components, constant_ids = self.extract_constants()
        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        deterministic_truncated_xor_differential = constraints
        self.middle_round = middle_round
        
        components_to_invert = []
        forward_components = []
        for component in self._cipher.get_all_components():
            comp_r = self.get_component_round(component.id)
            if comp_r >= initial_round - 1 and comp_r <= middle_round - 1 or comp_r > final_round - 1:
                forward_components.append(component)
            if comp_r > final_round - 1 and component.id not in key_ids + constant_ids:
                components_to_invert.append(component)
        backward_components = []
        for component in inverse_cipher.get_all_components():
            comp_r = self.get_component_round(component.id)
            if comp_r < initial_round - 1 or comp_r >= middle_round - 1 and comp_r <= final_round - 1:
                backward_components.append(component)
            if comp_r >= middle_round - 1 and comp_r <= final_round - 1 and component.id not in key_ids + constant_ids:
                components_to_invert.append(component)
        
        direct_variables, direct_constraints = self.build_impossible_forward_model(forward_components)
        inverse_variables, inverse_constraints = self.build_impossible_backward_model(backward_components, clean = False)
        
        variables, constraints = self.clean_inverse_impossible_variables_constraints(components_to_invert, direct_variables + inverse_variables, direct_constraints + inverse_constraints)
        
        self._variables_list.extend(variables)
        deterministic_truncated_xor_differential.extend(constraints)
        variables, constraints = self.input_impossible_attack_constraints(number_of_rounds, middle_round)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        deterministic_truncated_xor_differential.extend(self.final_impossible_attack_constraints(number_of_rounds, initial_round, middle_round, final_round, intermediate_components))
        set_of_constraints = self._variables_list + deterministic_truncated_xor_differential
        
        self._model_constraints = self._model_prefix + self.clean_constraints(set_of_constraints, initial_round, middle_round, final_round)
    '''        

    def build_impossible_xor_differential_trail_model(self, fixed_variables=[], number_of_rounds=None, initial_round = 1, middle_round=1, final_round = None, intermediate_components = True):
        """
        Build the CP model for the search of deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: cp.build_impossible_xor_differential_trail_model(fixed_variables)
        """
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        if final_round is None:
            final_round = self._cipher.number_of_rounds
        inverse_cipher = self.inverse_cipher

        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        deterministic_truncated_xor_differential = constraints
        self.middle_round = middle_round

        forward_components = []
        for r in range(middle_round):
            forward_components.extend(self._cipher.get_components_in_round(r))
        backward_components = []
        for r in range(number_of_rounds - middle_round + 1):
            backward_components.extend(inverse_cipher.get_components_in_round(r))
        
        direct_variables, direct_constraints = self.build_impossible_forward_model(forward_components)
        self._variables_list.extend(direct_variables)
        deterministic_truncated_xor_differential.extend(direct_constraints)

        inverse_variables, inverse_constraints = self.build_impossible_backward_model(backward_components)
        self._variables_list.extend(inverse_variables)
        deterministic_truncated_xor_differential.extend(inverse_constraints)

        variables, constraints = self.input_impossible_constraints(number_of_rounds = number_of_rounds, middle_round = middle_round)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        deterministic_truncated_xor_differential.extend(self.final_impossible_constraints(number_of_rounds, initial_round, middle_round, final_round, intermediate_components))
        set_of_constraints = self._variables_list + deterministic_truncated_xor_differential
        
        self._model_constraints = self._model_prefix + self.clean_constraints(set_of_constraints, initial_round, middle_round, final_round)
        
    def clean_constraints(self, set_of_constraints, initial_round, middle_round, final_round):
        number_of_rounds = self._cipher.number_of_rounds
        input_component = 'plaintext'
        model_constraints = []
        forward_components = []
        for r in range(initial_round - 1, middle_round):
            forward_components.extend([component.id for component in self._cipher.get_components_in_round(r)])
        backward_components = []
        for r in range(number_of_rounds - final_round, number_of_rounds - middle_round + 1):
            backward_components.extend(['inverse_' + component.id for component in self.inverse_cipher.get_components_in_round(r)])
        key_components, key_ids = self.extract_key_schedule()
        components_to_keep = forward_components + backward_components + key_ids + ['inverse_' + id_link for id_link in key_ids] + ['array['] + [solve_satisfy]
        if initial_round == 1 and final_round == self._cipher.number_of_rounds:
            for i in range(len(set_of_constraints) - 1):
                if set_of_constraints[i] not in set_of_constraints[i+1:]:
                    model_constraints.append(set_of_constraints[i])
            model_constraints.append(set_of_constraints[-1])
            return model_constraints
        if initial_round == 1:
            components_to_keep.extend(self._cipher.inputs)
        if final_round == number_of_rounds:
            components_to_keep.extend(['inverse_' + id_link for id_link in self.inverse_cipher.inputs])
        if initial_round > 1:
            for component in self._cipher.get_components_in_round(initial_round - 2):
                if 'output' in component.id:
                    components_to_keep.append(component.id)
                    input_component = component
        for constraint in set_of_constraints:
            for id_link in components_to_keep:
                if id_link in constraint and constraint not in model_constraints:
                    model_constraints.append(constraint)
                    
        return model_constraints
            
    def clean_inverse_impossible_variables_constraints(self, backward_components, inverse_variables, inverse_constraints):
        for component in backward_components:
            for v in range(len(inverse_variables)):
                start = 0
                while component.id in inverse_variables[v][start:]:
                    new_start = inverse_variables[v].index(component.id, start)
                    inverse_variables[v] = inverse_variables[v][:new_start] + 'inverse_' + inverse_variables[v][new_start:]
                    start = new_start + 9
            for c in range(len(inverse_constraints)):
                start = 0
                while component.id in inverse_constraints[c][start:]:
                    new_start = inverse_constraints[c].index(component.id, start)
                    inverse_constraints[c] = inverse_constraints[c][:new_start] + 'inverse_' + inverse_constraints[c][new_start:]
                    start = new_start + 9
        for c in range(len(inverse_constraints)):
            start = 0
            while 'cipher_output' in inverse_constraints[c][start:]:
                new_start = inverse_constraints[c].index('cipher_output', start)
                inverse_constraints[c] = inverse_constraints[c][:new_start] + 'inverse_' + inverse_constraints[c][new_start:]
                start = new_start + 9
            start = 0
            while 'inverse_inverse_' in inverse_constraints[c][start:]:
                new_start = inverse_constraints[c].index('inverse_inverse_', start)
                inverse_constraints[c] = inverse_constraints[c][:new_start] + inverse_constraints[c][new_start + 8:]
                start = new_start
        for v in range(len(inverse_variables)):
            start = 0
            while 'inverse_inverse_' in inverse_variables[v][start:]:
                new_start = inverse_variables[v].index('inverse_inverse_', start)
                inverse_variables[v] = inverse_variables[v][:new_start] + inverse_variables[v][new_start + 8:]
                start = new_start
        return inverse_variables, inverse_constraints
        
    def extract_incompatibilities_from_output(self, components_values, initial_round = None, final_round = None):
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        if initial_round is None or initial_round == 1:
            incompatibilities = {'plaintext': components_values['plaintext']}
        else:
            for component in cipher.get_components_in_round(initial_round - 2):
                if 'output' in component.id and component.id in components_values.keys():
                    incompatibilities = {component.id: components_values[component.id]}
        for component in cipher.get_all_components():
            if 'inverse_' + component.id in components_values.keys():
                incompatibility = False
                input_id_links = component.input_id_links
                input_bit_positions = component.input_bit_positions
                total_component_value = ''
                todo = True
                for id_link in input_id_links:
                    if id_link not in components_values.keys():
                        todo = False
                if todo:
                    for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                        for b in bit_positions:
                            total_component_value += components_values[id_link]['value'][b]
                    if len(total_component_value) == len(components_values['inverse_' + component.id]['value']):
                        for i in range(len(total_component_value)):
                            if int(total_component_value[i]) + int(components_values['inverse_' + component.id]['value'][i]) == 1:
                                incompatibility = True
                        if incompatibility:
                            for id_link in input_id_links:
                                incompatibilities[id_link] = components_values[id_link]
                            incompatibilities['inverse_' + component.id] = components_values['inverse_' + component.id]
                    else:
                        l = len(components_values['inverse_' + component.id]['value'])
                        for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                            for inverse_component in inverse_cipher.get_all_components():
                                if id_link == inverse_component.id and component.id in inverse_component.input_id_links and len(bit_positions) == l:
                                    for i in range(l):
                                        if int(components_values[id_link]['value'][i]) + int(components_values['inverse_' + component.id]['value'][i]) == 1:
                                            incompatibility = True
                            if incompatibility:
                                for id_link in input_id_links:
                                    incompatibilities[id_link] = components_values[id_link]
                                incompatibilities['inverse_' + component.id] = components_values['inverse_' + component.id]
                                incompatibility = False
        if final_round is None or final_round == cipher.number_of_rounds:
            incompatibilities['inverse_' + cipher.get_all_components_ids()[-1]] = components_values['inverse_' + cipher.get_all_components_ids()[-1]]
        else:
            for component in cipher.get_components_in_round(final_round - 1):
                if 'output' in component.id and 'inverse_' + component.id in components_values.keys():
                    incompatibilities['inverse_' + component.id] = components_values['inverse_' + component.id]
        
        solutions = {'solution1' : incompatibilities}
                    
        return solutions
        
    def extract_constants(self):
        cipher = self._cipher
        constant_components_ids = []
        constant_components = []
        for component in cipher.get_all_components():
            if 'constant' in component.id:
                constant_components_ids.append(component.id)
                constant_components.append(component)
            elif '_' in component.id:
                component_inputs = component.input_id_links
                ks = True
                for comp_input in component_inputs:
                    if 'constant' not in comp_input:
                        ks = False
                if ks:
                    constant_components_ids.append(component.id)
                    constant_components.append(component)
                
        return constant_components, constant_components_ids

    def extract_key_schedule(self):
        cipher = self._cipher
        key_schedule_components_ids = ['key']
        key_schedule_components = []
        for component in cipher.get_all_components():
            component_inputs = component.input_id_links
            ks = True
            for comp_input in component_inputs:
                if 'constant' not in comp_input and comp_input not in key_schedule_components_ids:
                    ks = False
            if ks:
                key_schedule_components_ids.append(component.id)
                key_schedule_components.append(component)
                master_key_bits = []
                for id_link, bit_positions in zip(component_inputs, component.input_bit_positions):
                    if id_link == 'key':
                        master_key_bits.extend(bit_positions)
                    else:
                        if id_link in self.key_schedule_bits_distribution:
                            master_key_bits.extend(self.key_schedule_bits_distribution[id_link])
                self.key_schedule_bits_distribution[component.id] = list(set(master_key_bits))
                    
        return key_schedule_components, key_schedule_components_ids

    '''
    def final_impossible_attack_constraints(self, number_of_rounds, initial_round, middle_round, final_round, intermediate_components):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_impossible_constraints(2)[:-2]
            ['solve satisfy;']
        """
        key_schedule_components, key_schedule_components_ids = self.extract_key_schedule()
        cipher_inputs = self._cipher.inputs
        for component in self._cipher.get_components_in_round(initial_round - 2):
            if 'output' in component.id:
                cipher_inputs.append(component.id)
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        cipher_outputs = []
        inverse_cipher_inputs = inverse_cipher.inputs
        for component in self.inverse_cipher.get_components_in_round(self._cipher.number_of_rounds - final_round):
            if 'output' in component.id:
                inverse_cipher_inputs.append(component.id)
        for id_link in inverse_cipher_inputs:
            if id_link not in key_schedule_components_ids:
                cipher_outputs.append(id_link)
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        incompatibility_constraint = 'constraint'
        key_schedule_components, key_schedule_components_ids = self.extract_key_schedule()
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for element in cipher_outputs:
            new_constraint = f'{new_constraint}\"inverse_{element} = \"++ show(inverse_{element}) ++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        for id_link in self._cipher.get_all_components_ids():
            if id_link not in key_schedule_components_ids and self.get_component_round(id_link) < middle_round and 'constant' not in id_link:
                new_constraint = new_constraint + f'\"{id_link} = \"++ show({id_link})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            if id_link not in key_schedule_components_ids and self.get_component_round(id_link) > middle_round - 2 and 'constant' not in id_link:
                new_constraint = new_constraint + f'\"inverse_{id_link} = \"++ show(inverse_{id_link})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        if intermediate_components:
            for component in cipher.get_components_in_round(middle_round-1):
                if component.type != CONSTANT and component.id not in key_schedule_components_ids:
                    component_id = component.id
                    input_id_links = component.input_id_links
                    input_bit_positions = component.input_bit_positions
                    component_inputs = []
                    input_bit_size = 0
                    for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                        component_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
                        input_bit_size += len(bit_positions)
                         #new_constraint = new_constraint + \
                         #   f'\"{id_link} = \"++ show({id_link})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    #new_constraint = new_constraint + \
                    #    f'\"inverse_{component_id} = \"++ show(inverse_{component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    for i in range(input_bit_size):
                        incompatibility_constraint += f'({component_inputs[i]}+inverse_{component_id}[{i}]=1) \\/ '
        else:
            for component in cipher.get_components_in_round(middle_round-1):
                if 'output' in component.id and component.id not in key_schedule_components_ids:
                    new_constraint = new_constraint + \
                    f'\"inverse_{component.id} = \"++ show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    new_constraint = new_constraint + \
                    f'\"inverse_{component.id} = \"++ show(inverse_{component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    for i in range(component.output_bit_size):
                        incompatibility_constraint += f'({component.id}[{i}]+inverse_{component.id}[{i}]=1) \\/ '
        incompatibility_constraint = incompatibility_constraint[:-4] + ';'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(incompatibility_constraint)
        cp_constraints.append(new_constraint)

        return cp_constraints
    '''
       
    def final_impossible_constraints(self, number_of_rounds, initial_round, middle_round, final_round, intermediate_components):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: cp = CpDeterministicTruncatedXorDifferentialModel(speck)
            sage: cp.final_impossible_constraints(2)[:-2]
            ['solve satisfy;']
        """
        if initial_round == 1:
            cipher_inputs = self._cipher.inputs
        else:
            cipher_inputs = ['key']
            for component in self._cipher.get_components_in_round(initial_round - 2):
                if 'output' in component.id:
                    cipher_inputs.append(component.id)
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        if final_round == self._cipher.number_of_rounds:
            cipher_outputs = inverse_cipher.inputs
        else:
            cipher_outputs = ['key']
            for component in self.inverse_cipher.get_components_in_round(self._cipher.number_of_rounds - final_round):
                if 'output' in component.id:
                    cipher_outputs.append(component.id)
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        incompatibility_constraint = 'constraint'
        key_schedule_components, key_schedule_components_ids = self.extract_key_schedule()
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for element in cipher_outputs:
            new_constraint = f'{new_constraint}\"inverse_{element} = \"++ show(inverse_{element}) ++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        if intermediate_components:
            for component in cipher.get_components_in_round(middle_round-1):
                if component.type != CONSTANT and component.id not in key_schedule_components_ids:
                    component_id = component.id
                    input_id_links = component.input_id_links
                    input_bit_positions = component.input_bit_positions
                    component_inputs = []
                    input_bit_size = 0
                    for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                        component_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
                        input_bit_size += len(bit_positions)
                        new_constraint = new_constraint + \
                            f'\"{id_link} = \"++ show({id_link})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    new_constraint = new_constraint + \
                        f'\"inverse_{component_id} = \"++ show(inverse_{component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    for i in range(input_bit_size):
                        incompatibility_constraint += f'({component_inputs[i]}+inverse_{component_id}[{i}]=1) \\/ '
        else:
            for component in cipher.get_all_components():
                if 'output' in component.id and component.id not in key_schedule_components_ids:
                    if self.get_component_round(component.id) <= middle_round - 1:
                        new_constraint = new_constraint + \
                        f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    if self.get_component_round(component.id) >= middle_round - 1:
                        new_constraint = new_constraint + \
                        f'\"inverse_{component.id} = \"++ show(inverse_{component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    if self.get_component_round(component.id) == middle_round - 1:
                        for i in range(component.output_bit_size):
                            incompatibility_constraint += f'({component.id}[{i}]+inverse_{component.id}[{i}]=1) \\/ '
        incompatibility_constraint = incompatibility_constraint[:-4] + ';'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(incompatibility_constraint)
        cp_constraints.append(new_constraint)

        return cp_constraints
        
    def find_all_impossible_xor_differential_trails(self, number_of_rounds, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``number_of_rounds`` -- **integer**; number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); can be created using ``set_fixed_variables`` method
        - ``solver_name`` -- **string** (default: `None`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import CpDeterministicTruncatedXorDifferentialModel
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
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
            sage: cp.find_all_deterministic_truncated_xor_differential_trail(3, [plaintext,key], 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r3',
              'components_values': {'cipher_output_2_12': {'value': '22222222222222202222222222222222',
                'weight': 0},
              ...
              'memory_megabytes': 0.02,
              'model_type': 'deterministic_truncated_xor_differential',
              'solver_name': 'Chuffed',
              'solving_time_seconds': 0.002,
              'total_weight': '0.0'}]
        """
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)

        return self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name, initial_round, middle_round, final_round, num_of_processors, timelimit)

    def find_lowest_complexity_impossible_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None):
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
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)
        self._model_constraints.remove(f'solve satisfy;')
        self._model_constraints.append(f'solve maximize count(plaintext, 0) + count(inverse_{self._cipher.get_all_components_ids()[-1]}, 0);')

        return self.solve('impossible_xor_differential_one_solution', solver_name, initial_round, middle_round, final_round, num_of_processors, timelimit)

    '''        
    def find_one_impossible_attack_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None):
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
        self.build_impossible_attack_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)

        return self.solve('impossible_xor_differential_one_solution', solver_name, initial_round, middle_round, final_round, num_of_processors, timelimit)
    '''
        
    def find_one_impossible_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None):
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
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)

        return self.solve('impossible_xor_differential_one_solution', solver_name, initial_round, middle_round, final_round, num_of_processors, timelimit)
        
    def get_component_round(self, id_link):
        if '_' in id_link:
            last_us = - id_link[::-1].index('_') - 1
            start = - id_link[last_us - 1::-1].index('_') + last_us
        
            return int(id_link[start:len(id_link) + last_us])
        else:
            return 0
        
    def get_inverse_state_key_bits_positions(self):
        key_bits = self.key_schedule_bits_distribution
        for component in self.inverse_cipher.get_all_components():
            if component.id not in key_bits:
                component_key_bits = []
                for id_link in component.input_id_links:
                    if id_link in key_bits:
                        component_key_bits.extend(key_bits[id_link])
                key_bits[component.id] = list(set(component_key_bits))
                        
        return key_bits
        
    def get_state_key_bits_positions(self):
        key_bits = self.key_schedule_bits_distribution
        for component in self._cipher.get_all_components():
            if component.id not in key_bits:
                component_key_bits = []
                for id_link in component.input_id_links:
                    if id_link in key_bits:
                        component_key_bits.extend(key_bits[id_link])
            key_bits[component.id] = list(set(component_key_bits))
                        
        return key_bits
       
    ''' 
    def input_impossible_attack_constraints(self, number_of_rounds=None, middle_round=None):
    
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        cp_constraints = []
        cp_declarations = [f'array[0..{bit_size - 1}] of var 0..2: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        
        key_components, key_ids = self.extract_key_schedule()
        constant_components, constant_ids = self.extract_constants()
        
        forward_components = []
        for component in self._cipher.get_all_components():
            n_round = self.get_component_round(component.id)
            if component.id in key_ids + constant_ids or n_round < middle_round:
                forward_components.append(component)
        backward_components = []
        for component in self.inverse_cipher.get_all_components():
            n_round = self.get_component_round(component.id)
            if component.id not in key_ids + constant_ids and n_round > middle_round - 2:
                backward_components.append(component)
                
        cp_declarations.extend([f'array[0..{bit_size - 1}] of var 0..2: inverse_{input_};' for input_, bit_size in zip(inverse_cipher.inputs, inverse_cipher.inputs_bit_size)])  
        for component in forward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
                cp_constraints.append(f'constraint count({output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
        for component in backward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
                cp_constraints.append(f'constraint count(inverse_{output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
        cp_constraints.append(f'constraint count(plaintext,2) < {self._cipher.output_bit_size};')
        for component in self._cipher.get_all_components():
            if CIPHER_OUTPUT in component.type:
                cp_constraints.append(f'constraint count(inverse_{component.id},2) < {self._cipher.output_bit_size};')

        return cp_declarations, cp_constraints
    '''

    def input_impossible_constraints(self, number_of_rounds=None, middle_round=None):
    
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        cp_constraints = []
        cp_declarations = [f'array[0..{bit_size - 1}] of var 0..2: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        forward_components = []
        for r in range(middle_round):
            forward_components.extend(self._cipher.get_components_in_round(r))
        backward_components = []
        for r in range(number_of_rounds - middle_round + 1):
            backward_components.extend(inverse_cipher.get_components_in_round(r))
        cp_declarations.extend([f'array[0..{bit_size - 1}] of var 0..2: inverse_{input_};' for input_, bit_size in zip(inverse_cipher.inputs, inverse_cipher.inputs_bit_size)])  
        for component in forward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
                cp_constraints.append(f'constraint count({output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
        for component in backward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
                cp_constraints.append(f'constraint count(inverse_{output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
        cp_constraints.append('constraint count(plaintext,1) > 0;')

        return cp_declarations, cp_constraints

    def _parse_solver_output(self, output_to_parse, model_type, initial_round, middle_round, final_round):
        """
        Parse solver solution (if needed).

        INPUT:

        - ``output_to_parse`` -- **list**; strings that represents the solver output
        - ``truncated`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import CpXorDifferentialTrailSearchModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, write_model_to_file
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: write_model_to_file(cp._model_constraints,'doctesting_file.mzn')
            sage: command = ['minizinc', '--solver-statistics', '--solver', 'Chuffed', 'doctesting_file.mzn']
            sage: import subprocess
            sage: solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            sage: os.remove('doctesting_file.mzn')
            sage: solver_output = solver_process.stdout.splitlines()
            sage: cp._parse_solver_output(solver_output) # random
            (0.018,
             ...
             'cipher_output_3_12': {'value': '0', 'weight': 0}}},
             ['0'])
        """
        components_values, memory, time = self.parse_solver_information(output_to_parse)
        all_components = [*self._cipher.inputs]
        for r in range(self.middle_round):
            all_components.extend([component.id for component in [*self._cipher.get_components_in_round(r)]])
        for r in range(self._cipher.number_of_rounds - self.middle_round + 1):
            all_components.extend(['inverse_' + component.id for component in [*self.inverse_cipher.get_components_in_round(r)]])
        all_components.extend(['inverse_' + id_link for id_link in [*self.inverse_cipher.inputs]])
        for component_id in all_components:
            solution_number = 1
            for j, string in enumerate(output_to_parse):
                if f'{component_id}' in string and 'inverse_' not in component_id + string:
                    value = self.format_component_value(component_id, string)
                    component_solution = {}
                    component_solution['value'] = value
                    self.add_solution_to_components_values(component_id, component_solution, components_values, j,
                                                           output_to_parse, solution_number, string)
                elif f'{component_id}' in string and 'inverse_' in component_id:
                    value = self.format_component_value(component_id, string)
                    component_solution = {}
                    component_solution['value'] = value
                    self.add_solution_to_components_values(component_id, component_solution, components_values, j,
                                                           output_to_parse, solution_number, string)
                elif '----------' in string:
                    solution_number += 1
        #if 'impossible' in model_type and solution_number > 1:
        #    components_values = self.extract_incompatibilities_from_output(components_values['solution1'], initial_round, final_round)

        return time, memory, components_values
            
    def solve(self, model_type, solver_name=None, initial_round=None, middle_round=None, final_round=None, num_of_processors=None, timelimit=None):
        """
        Return the solution of the model.

        INPUT:

        - ``model_type`` -- **string**; the model to solve:

          * 'cipher'
          * 'xor_differential'
          * 'xor_differential_one_solution'
          * 'xor_linear'
          * 'xor_linear_one_solution'
          * 'deterministic_truncated_xor_differential'
          * 'deterministic_truncated_xor_differential_one_solution'
          * 'impossible_xor_differential'
        - ``solver_name`` -- **string** (default: `None`); the name of the solver. Available values are:

          * ``'Chuffed'``
          * ``'Gecode'``
          * ``'COIN-BC'``

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import CpXorDifferentialTrailSearchModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = CpXorDifferentialTrailSearchModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', list(range(64)), integer_to_bit_list(0, 64, 'little')), set_fixed_variables('plaintext', 'not_equal', list(range(32)), integer_to_bit_list(0, 32, 'little'))]
            sage: cp.build_xor_differential_trail_model(-1, fixed_variables)
            sage: cp.solve('xor_differential', 'Chuffed') # random
            [{'cipher_id': 'speck_p32_k64_o32_r4',
              ...
              'total_weight': '7'},
             {'cipher_id': 'speck_p32_k64_o32_r4',
               ...
              'total_weight': '5'}]
        """
        
        cipher_name = self.cipher_id
        input_file_path = f'{cipher_name}_Cp_{model_type}_{solver_name}.mzn'
        command = self.get_command_for_solver_process(input_file_path, model_type, solver_name, num_of_processors, timelimit)
        solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        os.remove(input_file_path)
        if solver_process.returncode >= 0:
            solutions = []
            solver_output = solver_process.stdout.splitlines()
            if model_type in ['deterministic_truncated_xor_differential',
                              'deterministic_truncated_xor_differential_one_solution',
                              'impossible_xor_differential',
                              'impossible_xor_differential_one_solution',
                              'impossible_xor_differential_attack']:
                solve_time, memory, components_values = self._parse_solver_output(solver_output, model_type, initial_round, middle_round, final_round)
                total_weight = 0
            else:
                solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output, model_type)
            if components_values == {}:
                solution = convert_solver_solution_to_dictionary(self.cipher_id, model_type, solver_name,
                                                                 solve_time, memory,
                                                                 components_values, total_weight)
                if 'UNSATISFIABLE' in solver_output[0]:
                    solution['status'] = 'UNSATISFIABLE'
                else:
                    solution['status'] = 'SATISFIABLE'
                solutions.append(solution)
            else:
                self.add_solutions_from_components_values(components_values, memory, model_type, solutions, solve_time,
                                                          solver_name, solver_output)
            if model_type in ['xor_differential_one_solution',
                              'xor_linear_one_solution',
                              'deterministic_truncated_one_solution',
                              'impossible_xor_differential_one_solution']:
                return solutions[0]
            else:
                return solutions

