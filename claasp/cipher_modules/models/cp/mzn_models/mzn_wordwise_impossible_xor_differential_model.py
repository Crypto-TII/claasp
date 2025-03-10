
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
from copy import deepcopy

from claasp.cipher_modules.models.cp.mzn_model import solve_satisfy
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary, check_if_implemented_component, set_fixed_variables
from claasp.cipher_modules.models.cp.mzn_models.mzn_wordwise_deterministic_truncated_xor_differential_model import MznWordwiseDeterministicTruncatedXorDifferentialModel

from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, IMPOSSIBLE_XOR_DIFFERENTIAL)
from claasp.cipher_modules.models.cp.solvers import CP_SOLVERS_EXTERNAL, SOLVER_DEFAULT


class MznWordwiseImpossibleXorDifferentialModel(MznWordwiseDeterministicTruncatedXorDifferentialModel):

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
        key_components, key_ids = self.extract_key_schedule()
        constant_components, constant_ids = self.extract_constants()
        for component in backward_components:
            if check_if_implemented_component(component):
                variables, constraints = self.propagate_deterministically(component, wordwise=True, inverse=True)
                inverse_variables.extend(variables)
                inverse_constraints.extend(constraints)
        
        if clean:
            components_to_invert = [backward_components[i] for i in range(len(backward_components))]
            for component in backward_components:
                for id_link in component.input_id_links:
                    input_component = self.get_component_from_id(id_link, self.inverse_cipher)
                    if input_component not in backward_components and id_link not in key_ids + constant_ids:
                        components_to_invert.append(input_component)
            inverse_variables, inverse_constraints = self.clean_inverse_impossible_variables_constraints_with_extensions(components_to_invert, inverse_variables, inverse_constraints)
            
        return inverse_variables, inverse_constraints
    
    def build_impossible_forward_model(self, forward_components, clean = False):
        direct_variables = []
        direct_constraints = []
        for component in forward_components:
            if check_if_implemented_component(component):
                variables, constraints = self.propagate_deterministically(component, wordwise=True)
                direct_variables.extend(variables)
                direct_constraints.extend(constraints)
            
        if clean:
            direct_variables, direct_constraints = self.clean_inverse_impossible_variables_constraints(forward_components, direct_variables, direct_constraints)
            
        return direct_variables, direct_constraints
        
    def build_impossible_xor_differential_trail_with_extensions_model(self, fixed_variables, number_of_rounds, initial_round, middle_round, final_round, intermediate_components):
        """
        Build the CP model for the search of deterministic truncated XOR differential trails with extensions for key recovery.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``number_of_rounds`` -- **integer** ; number of rounds
        - ``initial_round`` -- **integer** ; initial round of the impossible differential trail
        - ``middle_round`` -- **integer** ; incosistency round of the impossible differential trail
        - ``final_round`` -- **integer** ; final round of the impossible differential trail
        - ``intermediate_components`` -- **Boolean** ; check inconsistency on intermediate components of the inconsistency round or only on outputs

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=5)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: cp.build_impossible_xor_differential_trail_with_extensions_model(fixed_variables, 5, 2, 3, 4, False)
        """
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        inverse_cipher = self.inverse_cipher
        if final_round is None:
            final_round = self._cipher.number_of_rounds - 1
        key_components, key_ids = self.extract_key_schedule()
        constant_components, constant_ids = self.extract_constants()
        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        deterministic_truncated_xor_differential = constraints
        self.middle_round = middle_round
        
        forward_components = []
        for n_r in list(range(initial_round - 1, middle_round)) + list(range(final_round, number_of_rounds)):
            forward_components.extend(self._cipher.get_components_in_round(n_r))
                
        backward_components = []
        for n_r in list(range(initial_round - 1)) + list(range(middle_round - 1, final_round)):
            backward_components.extend(inverse_cipher.get_components_in_round(number_of_rounds - 1 - n_r))
                
        components_to_link = []
        for component in self.inverse_cipher.get_all_components():
            comp_r = self.get_component_round(component.id)
            if comp_r == initial_round - 2 or comp_r == final_round - 1:
                for id_link in component.input_id_links:
                    if self.get_component_round(id_link) > comp_r:
                        for input_component in self.inverse_cipher.get_all_components():
                            if input_component.id == id_link:
                                components_to_link.append([self.get_inverse_component_correspondance(input_component), id_link])
                                
        link_constraints = self.link_constraints_for_trail_with_extensions(components_to_link)
        key_schedule_variables, key_schedule_constraints = self.constraints_for_key_schedule()
        constants_variables, constants_constraints = self.constraints_for_constants()
        
        direct_variables, direct_constraints = self.build_impossible_forward_model(forward_components)
        inverse_variables, inverse_constraints = self.build_impossible_backward_model(backward_components)
        
        variables = direct_variables + inverse_variables
        constraints = direct_constraints + inverse_constraints
        
        self._variables_list.extend(variables)
        self._variables_list.extend(key_schedule_variables)
        self._variables_list.extend(constants_variables)
        deterministic_truncated_xor_differential.extend(constraints)
        variables, constraints = self.input_impossible_constraints_with_extensions(number_of_rounds, initial_round, middle_round, final_round)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        deterministic_truncated_xor_differential.extend(link_constraints)
        deterministic_truncated_xor_differential.extend(key_schedule_constraints)
        deterministic_truncated_xor_differential.extend(constants_constraints)
        deterministic_truncated_xor_differential.extend(self.final_impossible_constraints_with_extensions(number_of_rounds, initial_round, middle_round, final_round, intermediate_components))
        set_of_constraints = self._variables_list + deterministic_truncated_xor_differential
        
        cleaned_constraints = []
        for constraint in self._model_prefix + set_of_constraints:
            if constraint not in cleaned_constraints:
                cleaned_constraints.append(constraint)
        
        self._model_constraints = cleaned_constraints
    
    def build_impossible_xor_differential_trail_model(self, fixed_variables=[], number_of_rounds=None, initial_round = 1, middle_round=1, final_round = None, intermediate_components = True):
        """
        Build the CP model for the search of deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``initial_round`` -- **integer** (default: `1`); initial round of the impossible differential
        - ``middle_round`` -- **integer** (default: `1`); incosistency round of the impossible differential
        - ``final_round`` -- **integer** (default: `None`); final round of the impossible differential
        - ``intermediate_components`` -- **Boolean** (default: `True`); check inconsistency on intermediate components of the inconsistency round or only on outputs

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: cp.build_impossible_xor_differential_trail_model(fixed_variables, 4, 1, 3, 4, False)
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

        if middle_round is not None:
            forward_components = []
            for r in range(middle_round):
                forward_components.extend(self._cipher.get_components_in_round(r))
            backward_components = []
            for r in range(number_of_rounds - middle_round + 1):
                backward_components.extend(inverse_cipher.get_components_in_round(r))
        else:
            forward_components = []
            for r in range(number_of_rounds):
                forward_components.extend(self._cipher.get_components_in_round(r))
            backward_components = []
            for r in range(number_of_rounds):
                backward_components.extend(inverse_cipher.get_components_in_round(r))
        
        direct_variables, direct_constraints = self.build_impossible_forward_model(forward_components)
        self._variables_list.extend(direct_variables)
        deterministic_truncated_xor_differential.extend(direct_constraints)

        inverse_variables, inverse_constraints = self.build_impossible_backward_model(backward_components, clean = False)
        inverse_variables, inverse_constraints = self.clean_inverse_impossible_variables_constraints(backward_components, inverse_variables, inverse_constraints)
        self._variables_list.extend(inverse_variables)
        deterministic_truncated_xor_differential.extend(inverse_constraints)

        self._model_prefix.append('\nfunction var int: TruncBitsToInt(array[int] of var 0..3: bits)=')
        self._model_prefix.append('if 3 in bits then -2 elseif 2 in bits then -1 else sum([bits[i]*2^(length(bits)-1-i) | i in 0..length(bits)-1]) endif;\n')

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
        if middle_round is not None:
            forward_components = []
            for r in range(initial_round - 1, middle_round):
                forward_components.extend([component.id for component in self._cipher.get_components_in_round(r)])
            backward_components = []
            for r in range(number_of_rounds - final_round, number_of_rounds - middle_round + 1):
                backward_components.extend(['inverse_' + component.id for component in self.inverse_cipher.get_components_in_round(r)])
        else:
            forward_components = []
            for r in range(initial_round - 1, final_round):
                forward_components.extend([component.id for component in self._cipher.get_components_in_round(r)])
            backward_components = []
            for r in range(number_of_rounds - final_round, number_of_rounds - initial_round + 1):
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
            inverse_variables, inverse_constraints = self.set_inverse_component_id_in_constraints(component, inverse_variables, inverse_constraints)
        inverse_variables, inverse_constraints = self.clean_repetitions_in_constraints(inverse_variables, inverse_constraints)
        return inverse_variables, inverse_constraints
        
    def clean_inverse_impossible_variables_constraints_with_extensions(self, backward_components, inverse_variables, inverse_constraints):
        key_components, key_ids = self.extract_key_schedule()
        constant_components, constant_ids = self.extract_constants()
        for component in backward_components:
            if component.id not in key_ids + constant_ids:
                inverse_variables, inverse_constraints = self.set_inverse_component_id_in_constraints(component, inverse_variables, inverse_constraints)
        inverse_variables, inverse_constraints = self.clean_repetitions_in_constraints(inverse_variables, inverse_constraints)
        return inverse_variables, inverse_constraints
        
    def clean_repetitions_in_constraints(self, inverse_variables, inverse_constraints):
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
        
    def constraints_for_key_schedule(self):
        key_components, key_ids = self.extract_key_schedule()
        return self.build_impossible_forward_model(key_components)
        
    def constraints_for_constants(self):
        constant_components, constant_ids = self.extract_constants()
        return self.build_impossible_forward_model(constant_components)
        
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

    def final_impossible_constraints_with_extensions(self, number_of_rounds, initial_round, middle_round, final_round, intermediate_components):
        """
        Constraints for output and incompatibility.

        INPUT:

        - ``number_of_rounds`` -- **integer** ; number of rounds
        - ``initial_round`` -- **integer** ; initial round of the impossible differential trail
        - ``middle_round`` -- **integer** ; incosistency round of the impossible differential trail
        - ``final_round`` -- **integer** ; final round of the impossible differential trail
        - ``intermediate_components`` -- **Boolean** ; check inconsistency on intermediate components of the inconsistency round or only on outputs

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=5)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: cp.final_impossible_constraints_with_extensions(5, 2, 3, 4, False)
            ['solve satisfy;',
             ...
             'output["plaintext = "++ show(plaintext) ++ "\\n" ++"key = "++ show(key) ++ "\\n" ++"inverse_plaintext = "++ show(inverse_plaintext) ++ "\\n" ++"inverse_intermediate_output_0_6 = "++ show(inverse_intermediate_output_0_6)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_12 = "++ show(intermediate_output_1_12)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_2_12 = "++ show(intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_12 = "++ show(inverse_intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_3_12 = "++ show(inverse_intermediate_output_3_12)++ "\\n" ++ "0" ++ "\\n" ++"cipher_output_4_12 = "++ show(cipher_output_4_12)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_2_12 = "++ show(intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_12 = "++ show(inverse_intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ];']
        """
        key_schedule_components, key_schedule_components_ids = self.extract_key_schedule()
        cipher_inputs = self._cipher.inputs
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        incompatibility_constraint = 'constraint '
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for element in cipher_inputs:
            if element not in key_schedule_components_ids:
                new_constraint = f'{new_constraint}\"inverse_{element} = \"++ show(inverse_{element}) ++ \"\\n\" ++'
        for id_link in self._cipher.get_all_components_ids():
            if id_link not in key_schedule_components_ids and self.get_component_round(id_link) in list(range(initial_round - 1, middle_round)) + list(range(final_round, number_of_rounds)) and 'constant' not in id_link and 'output' in id_link:
                new_constraint = new_constraint + f'\"{id_link} = \"++ show({id_link})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            if id_link not in key_schedule_components_ids and self.get_component_round(id_link) in list(range(initial_round - 1)) + list(range(middle_round - 1, final_round)) and 'constant' not in id_link and 'output' in id_link:
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
                    f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    new_constraint = new_constraint + \
                    f'\"inverse_{component.id} = \"++ show(inverse_{component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    for i in range(component.output_bit_size):
                        incompatibility_constraint += f'({component.id}[{i}]+inverse_{component.id}[{i}]=1) \\/ '
        incompatibility_constraint = incompatibility_constraint[:-4] + ';'
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(incompatibility_constraint)
        cp_constraints.append(new_constraint)

        return cp_constraints
    
    def final_impossible_constraints(self, number_of_rounds, initial_round, middle_round, final_round, intermediate_components):
        """
        Constraints for output and incompatibility.

        INPUT:

        - ``number_of_rounds`` -- **integer** ; number of rounds
        - ``initial_round`` -- **integer** ; initial round of the impossible differential trail
        - ``middle_round`` -- **integer** ; incosistency round of the impossible differential trail
        - ``final_round`` -- **integer** ; final round of the impossible differential trail
        - ``intermediate_components`` -- **Boolean** ; check inconsistency on intermediate components of the inconsistency round or only on outputs

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=5)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: cp.final_impossible_constraints(3, 2, 3, 4, False)
            ['solve satisfy;',
             ...
             'output["key = "++ show(key) ++ "\\n" ++"intermediate_output_0_5 = "++ show(intermediate_output_0_5) ++ "\\n" ++"intermediate_output_0_6 = "++ show(intermediate_output_0_6) ++ "\\n" ++"inverse_key = "++ show(inverse_key) ++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_3_12 = "++ show(inverse_intermediate_output_3_12) ++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_0_6 = "++ show(intermediate_output_0_6)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_12 = "++ show(intermediate_output_1_12)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_2_12 = "++ show(intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_12 = "++ show(inverse_intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_3_12 = "++ show(inverse_intermediate_output_3_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_cipher_output_4_12 = "++ show(inverse_cipher_output_4_12)++ "\\n" ++ "0" ++ "\\n" ];']
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
        incompatibility_constraint = 'constraint '
        key_schedule_components, key_schedule_components_ids = self.extract_key_schedule()
        for element in cipher_inputs:
            new_constraint = f'{new_constraint}\"{element}_active = \"++ show({element}_active) ++ \"\\n\" ++'
            new_constraint = f'{new_constraint}\"{element}_value = \"++ show({element}_value) ++ \"\\n\" ++'
        for element in cipher_outputs:
            new_constraint = f'{new_constraint}\"inverse_{element}_active = \"++ show(inverse_{element}_active) ++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
            new_constraint = f'{new_constraint}\"inverse_{element}_value = \"++ show(inverse_{element}_value) ++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
        if intermediate_components:
            if middle_round is not None:
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
                                f'\"{id_link}_active = \"++ show({id_link}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                                f'\"{id_link}_value = \"++ show({id_link}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        new_constraint = new_constraint + \
                            f'\"inverse_{component_id}_active= \"++ show(inverse_{component_id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                            f'\"inverse_{component_id}_value = \"++ show(inverse_{component_id}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        for i in range(input_bit_size):
                            incompatibility_constraint += f'({component_inputs[i]}_active>=0 /\\ inverse_{component_id}_active>=0 /\\ floor({component_inputs[i]}_value/2^{i}) mod 2 != floor(inverse_{component_id}_value/2^{i}) mod 2 \\/ '
            else:
                for component in cipher.get_all_components():
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
                                f'\"{id_link}_active = \"++ show({id_link}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                                f'\"{id_link}_value = \"++ show({id_link}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        new_constraint = new_constraint + \
                            f'\"inverse_{component_id}_active= \"++ show(inverse_{component_id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                            f'\"inverse_{component_id}_value = \"++ show(inverse_{component_id}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        for i in range(input_bit_size):
                            incompatibility_constraint += f'({component_inputs[i]}_active>=0 /\\ inverse_{component_id}_active>=0 /\\ floor({component_inputs[i]}_value/2^{i}) mod 2 != floor(inverse_{component_id}_value/2^{i}) mod 2 \\/ '
        else:
            if middle_round is not None:
                for component in cipher.get_all_components():
                    if 'output' in component.id and component.id not in key_schedule_components_ids:
                        if self.get_component_round(component.id) <= middle_round - 1:
                            new_constraint = new_constraint + \
                            f'\"{component.id}_active = \"++ show({component.id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                            f'\"{component.id}_value = \"++ show({component.id}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        if self.get_component_round(component.id) >= middle_round - 1:
                            new_constraint = new_constraint + \
                            f'\"inverse_{component.id}_active = \"++ show(inverse_{component.id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                            f'\"inverse_{component.id}_value = \"++ show(inverse_{component.id}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        if self.get_component_round(component.id) == middle_round - 1:
                            for i in range(component.output_bit_size // self.word_size):
                                incompatibility_constraint += f'{component.id}_active[{i}] = 0 /\\ inverse_{component.id}_active[{i}] = 2 \\/ '
                                incompatibility_constraint += f'{component.id}_active[{i}] = 2 /\\ inverse_{component.id}_active[{i}] = 0 \\/ '
                                for j in range(self.word_size):
                                    incompatibility_constraint += f'({component.id}_active[{i}] < 2 /\\ inverse_{component.id}_active[{i}] < 2 /\\ floor({component.id}_value[{i}]/2^{j}) mod 2 != floor(inverse_{component.id}_value[{i}]/2^{j}) mod 2) \\/ '
            else:
                for component in cipher.get_all_components():
                    if 'output' in component.id and component.id not in key_schedule_components_ids:
                        new_constraint = new_constraint + \
                        f'\"{component.id}_active = \"++ show({component.id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                        f'\"{component.id}_value = \"++ show({component.id}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        new_constraint = new_constraint + \
                        f'\"inverse_{component.id}_active = \"++ show(inverse_{component.id}_active)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++' + \
                        f'\"inverse_{component.id}_value = \"++ show(inverse_{component.id}_value)++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        for i in range(component.output_bit_size // self.word_size):
                            incompatibility_constraint += f'{component.id}_active[{i}] = 0 /\\ inverse_{component.id}_active[{i}] = 2 \\/ '
                            incompatibility_constraint += f'{component.id}_active[{i}] = 2 /\\ inverse_{component.id}_active[{i}] = 0 \\/ '
                            for j in range(self.word_size):
                                incompatibility_constraint += f'({component.id}_active[{i}] < 2 /\\ inverse_{component.id}_active[{i}] < 2 /\\ floor({component.id}_value[{i}]/2^{j}) mod 2 != floor(inverse_{component.id}_value[{i}]/2^{j}) mod 2) \\/ '
        incompatibility_constraint = incompatibility_constraint[:-4] + ';'
        #new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(incompatibility_constraint)
        #cp_constraints.append(new_constraint)

        return cp_constraints
        
    def find_all_impossible_xor_differential_trails(self, number_of_rounds, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = True):
        """
        Search for all impossible XOR differential trails of a cipher.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``initial_round`` -- **integer** (default: `1`); initial round of the impossible differential
        - ``middle_round`` -- **integer** (default: `1`); incosistency round of the impossible differential
        - ``final_round`` -- **integer** (default: `None`); final round of the impossible differential
        - ``intermediate_components`` -- **Boolean** (default: `True`); check inconsistency on intermediate components of the inconsistency round or only on outputs
        - ``num_of_processors`` -- **Integer** (default: `None`); number of processors used for MiniZinc search
        - ``timelimit`` -- **Integer** (default: `None`); time limit of MiniZinc search

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_3_12', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: trail = cp.find_all_impossible_xor_differential_trails(4, fixed_variables, 'Chuffed', 1, 3, 4, False) #doctest: +SKIP
            
        """
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)

        if solve_with_API:
            return self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, all_solutions_ = True)
        return self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name = solver_name, number_of_rounds = number_of_rounds, initial_round = initial_round, middle_round = middle_round, final_round = final_round, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, all_solutions_ = True, solve_external = solve_external)

    def find_lowest_complexity_impossible_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = True):
        """
        Search for the impossible XOR differential trail of a cipher with the highest number of known bits in plaintext and ciphertext difference.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``initial_round`` -- **integer** (default: `1`); initial round of the impossible differential
        - ``middle_round`` -- **integer** (default: `1`); incosistency round of the impossible differential
        - ``final_round`` -- **integer** (default: `None`); final round of the impossible differential
        - ``intermediate_components`` -- **Boolean** (default: `True`); check inconsistency on intermediate components of the inconsistency round or only on outputs
        - ``num_of_processors`` -- **Integer** (default: `None`); number of processors used for MiniZinc search
        - ``timelimit`` -- **Integer** (default: `None`); time limit of MiniZinc search

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_3_12', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: trail = cp.find_lowest_complexity_impossible_xor_differential_trail(4, fixed_variables, 'Chuffed', 1, 3, 4, intermediate_components = False)
        """
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)
        self._model_constraints.remove(f'solve satisfy;')
        self._model_constraints.append(f'solve minimize count(plaintext, 2) + count(inverse_{self._cipher.get_all_components_ids()[-1]}, 2);')

        if solve_with_API:
            return self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        return self.solve('impossible_xor_differential_one_solution', solver_name = solver_name, number_of_rounds = number_of_rounds, initial_round = initial_round, middle_round = middle_round, final_round = final_round, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)
      
    def find_one_impossible_xor_differential_trail_with_extensions(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = True):
        """
        Search for one impossible XOR differential trail of a cipher with forward and backward deterministic extensions for key recovery.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``initial_round`` -- **integer** (default: `1`); initial round of the impossible differential
        - ``middle_round`` -- **integer** (default: `1`); incosistency round of the impossible differential
        - ``final_round`` -- **integer** (default: `None`); final round of the impossible differential
        - ``intermediate_components`` -- **Boolean** (default: `True`); check inconsistency on intermediate components of the inconsistency round or only on outputs
        - ``num_of_processors`` -- **Integer** (default: `None`); number of processors used for MiniZinc search
        - ``timelimit`` -- **Integer** (default: `None`); time limit of MiniZinc search

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=7)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: fixed_variables.append(set_fixed_variables('cipher_output_6_12', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: trail = cp.find_one_impossible_xor_differential_trail_with_extensions(7, fixed_variables, 'Chuffed', 2, 4, 6, intermediate_components = False)
        """
        self.build_impossible_xor_differential_trail_with_extensions_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)

        if solve_with_API:
            return self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        return self.solve('impossible_xor_differential_one_solution', solver_name = solver_name, number_of_rounds = number_of_rounds, initial_round = initial_round, middle_round = middle_round, final_round = final_round, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)
    
    def find_one_impossible_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = True):
        """
        Search for one impossible XOR differential trail of a cipher.

        INPUT:

        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``initial_round`` -- **integer** (default: `1`); initial round of the impossible differential
        - ``middle_round`` -- **integer** (default: `1`); incosistency round of the impossible differential
        - ``final_round`` -- **integer** (default: `None`); final round of the impossible differential
        - ``intermediate_components`` -- **Boolean** (default: `True`); check inconsistency on intermediate components of the inconsistency round or only on outputs
        - ``num_of_processors`` -- **Integer** (default: `None`); number of processors used for MiniZinc search
        - ``timelimit`` -- **Integer** (default: `None`); time limit of MiniZinc search

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import MznImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_3_12', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: trail = cp.find_one_impossible_xor_differential_trail(4, fixed_variables, 'Chuffed', 1, 3, 4, intermediate_components = False)
        """
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)
        
        if solve_with_API:
            return self.solve_for_ARX(solver_name = solver_name, timeout_in_seconds_ = timelimit, processes_ = num_of_processors)
        return self.solve('impossible_xor_differential_one_solution', solver_name = solver_name, number_of_rounds = number_of_rounds, initial_round = initial_round, middle_round = middle_round, final_round = final_round, timeout_in_seconds_ = timelimit, processes_ = num_of_processors, solve_external = solve_external)
    
    def fix_variables_value_constraints(self, fixed_variables=[], step='full_model'):
        r"""
        Return a list of CP constraints that fix the input variables to a specific value.

        INPUT:

        - ``fixed_variables`` -- **list**  (default: `[]`); dictionaries containing name, bit_size,
          value (as integer) for the variables that need to be fixed to a certain value:

          {
              'component_id': 'plaintext',

              'constraint_type': 'equal'/'not_equal'

              'bit_size': 32,

              'value': 753

          }
        - ``step`` -- **string** (default: `full_model`)

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznModel(speck)
            sage: cp.fix_variables_value_constraints([set_fixed_variables('plaintext', 'equal', range(4), integer_to_bit_list(5, 4, 'big'))])
            ['constraint plaintext[0] = 0 /\\ plaintext[1] = 1 /\\ plaintext[2] = 0 /\\ plaintext[3] = 1;']
            sage: cp.fix_variables_value_constraints([set_fixed_variables('plaintext', 'not_equal', list(range(4)), integer_to_bit_list(5, 4, 'big'))])
            ['constraint plaintext[0] != 0 \\/ plaintext[1] != 1 \\/ plaintext[2] != 0 \\/ plaintext[3] != 1;']
        """
        cp_constraints = []
        if fixed_variables == []:
            plaintext = set_fixed_variables('plaintext', 'not_equal', list(range(self._cipher.output_bit_size)), [0]*self._cipher.output_bit_size)
            ciphertext = set_fixed_variables('inverse_' + self._cipher.get_all_components_ids()[-1], 'not_equal', list(range(self._cipher.output_bit_size)), [0]*self._cipher.output_bit_size)
            for cipher_input, bit_size in zip(self._cipher._inputs, self._cipher._inputs_bit_size):
                if cipher_input == 'key':
                    key = set_fixed_variables('key', 'equal', list(range(bit_size)), [0]*bit_size)
            fixed_variables = [plaintext, ciphertext, key]
        for component in fixed_variables:
            component_id = component['component_id']
            bit_positions = component['bit_positions']
            bit_values = component['bit_values']
            input_length = len(bit_positions) // self.word_size
            bit_positions = self.calculate_bit_positions(bit_positions, input_length)
            bit_values = self.calculate_bit_values(bit_values, input_length)
            if component['constraint_type'] == 'equal':
                sign = '='
                logic_operator = ' /\\ '
            elif component['constraint_type'] == 'not_equal':
                sign = '!='
                logic_operator = ' \\/ '
            else:
                raise ValueError(constraint_type_error)
            values_constraints = [f'{component_id}[{position}] {sign} {bit_values[i]}'
                                  for i, position in enumerate(bit_positions)]
            new_constraint = 'constraint ' + f'{logic_operator}'.join(values_constraints) + ';'
            cp_constraints.append(new_constraint)

        return cp_constraints

    def get_component_from_id(self, id_link, curr_cipher):
        for component in curr_cipher.get_all_components():
            if component.id == id_link:
                return component
        return None
    
    def get_component_round(self, id_link):
        if '_' in id_link:
            last_us = - id_link[::-1].index('_') - 1
            start = - id_link[last_us - 1::-1].index('_') + last_us
        
            return int(id_link[start:len(id_link) + last_us])
        else:
            return 0
        
    def get_direct_component_correspondance(self, forward_component):
        for inverse_component in self.inverse_cipher.get_all_components():
            if inverse_component.get_inverse_component_correspondance(inverse_component) == forward_component:
                return inverse_component
                    
    def get_inverse_component_correspondance(self, backward_component):
        
        for component in self._cipher.get_all_components():
            if backward_component.id == component.id:
                direct_inputs = component.input_id_links
        inverse_outputs = []
        for component in self.inverse_cipher.get_all_components():
            if backward_component.id in component.input_id_links:
                inverse_outputs.append(component.id)
        correspondance = [dir_i for dir_i in direct_inputs if dir_i in inverse_outputs]
        if len(correspondance) > 1:
            return 'Not invertible'
        else:
            return correspondance[0]

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
       
    def input_impossible_constraints_with_extensions(self, number_of_rounds=None, initial_round=None, middle_round=None, final_round=None):
    
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
            comp_r = self.get_component_round(component.id)
            if comp_r >= initial_round - 1 and comp_r <= middle_round - 1 or comp_r > final_round - 1:
                forward_components.append(component)
        components_to_direct = []
        for component in forward_components:
            for id_link in component.input_id_links:
                input_component = self.get_component_from_id(id_link, cipher)
                if input_component not in key_ids + constant_ids + forward_components + components_to_direct and input_component != None:
                    components_to_direct.append(input_component)
        forward_components.extend(components_to_direct)
        forward_components.extend(key_components)
        forward_components.extend(constant_components)
                    
        backward_components = []
        for component in inverse_cipher.get_all_components():
            comp_r = self.get_component_round(component.id)
            if comp_r < initial_round - 1 or comp_r >= middle_round - 1 and comp_r <= final_round - 1:
                backward_components.append(component)
        components_to_invert = []
        for component in backward_components:
            for id_link in component.input_id_links:
                input_component = self.get_component_from_id(id_link, inverse_cipher)
                if input_component not in key_ids + constant_ids + backward_components + components_to_invert and input_component != None:
                    components_to_invert.append(input_component)
        backward_components.extend(components_to_invert)
                  
        for component in forward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
                cp_constraints.append(f'constraint count({output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: {output_id_link};')
                
        for component in backward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
                cp_constraints.append(f'constraint count(inverse_{output_id_link},2) < {output_size};')
                if self.get_component_round(component.id) == final_round - 1 or self.get_component_round(component.id) == initial_round - 2:
                    cp_constraints.append(f'constraint count(inverse_{output_id_link},1) > 0;')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..2: inverse_{output_id_link};')
                
        cp_constraints.append(f'constraint count(plaintext,2) < {self._cipher.output_bit_size};')
        
        for component in self._cipher.get_all_components():
            if CIPHER_OUTPUT in component.type:
                cp_constraints.append(f'constraint count({component.id},2) < {self._cipher.output_bit_size};')

        return cp_declarations, cp_constraints
    
    def input_impossible_constraints(self, number_of_rounds=None, middle_round=None):
        inverse_cipher = self.inverse_cipher
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

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
        if middle_round is not None:
            forward_components = []
            for r in range(middle_round):
                forward_components.extend(self._cipher.get_components_in_round(r))
            backward_components = []
            for r in range(number_of_rounds - middle_round + 1):
                backward_components.extend(inverse_cipher.get_components_in_round(r))
        else:
            forward_components = []
            for r in range(number_of_rounds):
                forward_components.extend(self._cipher.get_components_in_round(r))
            backward_components = []
            for r in range(number_of_rounds):
                backward_components.extend(inverse_cipher.get_components_in_round(r))
        for input_, bit_size in zip(inverse_cipher.inputs, inverse_cipher.inputs_bit_size):
            cp_declarations.append(f'array[0..{bit_size // self.word_size - 1}] of var 0..3: inverse_{input_}_active;')
            cp_declarations.append(
                f'array[0..{bit_size // self.word_size - 1}] of var -2..{2 ** self.word_size - 1}: inverse_{input_}_value;')
            for i in range(bit_size // self.word_size):
                cp_constraints.append(f'constraint if inverse_{input_}_active[{i}] == 0 then inverse_{input_}_value[{i}] = 0 elseif '
                                      f'inverse_{input_}_active[{i}] == 1 then inverse_{input_}_value[{i}] > 0 elseif '
                                      f'inverse_{input_}_active[{i}] == 2 then inverse_{input_}_value[{i}] =-1 else '
                                      f'inverse_{input_}_value[{i}] =-2 endif;')
        for component in forward_components:
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
        for component in backward_components:
            if CONSTANT not in component.type:
                output_id_link = component.id
                output_size = int(component.output_bit_size)
                cp_declarations.append(
                    f'array[0..{output_size // self.word_size - 1}] of var 0..3: inverse_{output_id_link}_active;')
                cp_declarations.append(
                    f'array[0..{output_size // self.word_size - 1}] of var -2..{2 ** self.word_size - 1}: '
                    f'inverse_{output_id_link}_value;')
                for i in range(output_size // self.word_size):
                    cp_constraints.append(
                        f'constraint if inverse_{output_id_link}_active[{i}] == 0 then inverse_{output_id_link}_value[{i}] = 0 elseif '
                        f'inverse_{output_id_link}_active[{i}] == 1 then inverse_{output_id_link}_value[{i}] > 0 elseif '
                        f'inverse_{output_id_link}_active[{i}] == 2 then inverse_{output_id_link}_value[{i}] =-1 else '
                        f'inverse_{output_id_link}_value[{i}] =-2 endif;')
                if CIPHER_OUTPUT in component.type:
                    cp_constraints.append(f'constraint count(inverse_{output_id_link}_active,1) > 0;')
        cp_constraints.append('constraint count(plaintext_active,1) > 0;')
        for component in self._cipher.get_all_components():
            if CIPHER_OUTPUT in component.type:
                output_id_link = component.id
                cp_constraints.append(f'constraint count(inverse_{output_id_link}_active,1) > 0;')


        return cp_declarations, cp_constraints

    def is_cross_round_component(self, component, discarded_ids):
        component_round = self.get_component_round(component.id)
        for input_id in component.input_id_links:
            if input_id not in discarded_ids and self.get_component_round(input_id) != component_round:
                return True
        return False
         
    def link_constraints_for_trail_with_extensions(self, components_to_link):
        linking_constraints = []                        
        for pairs in components_to_link:
            linking_constraints.append(f'constraint {pairs[0]} = inverse_{pairs[1]};')
            
        return linking_constraints
        
    def _parse_solver_output(self, output_to_parse, number_of_rounds, initial_round, middle_round, final_round):
        components_values, memory, time = self.parse_solver_information(output_to_parse, True, True)
        all_components = [*self._cipher.inputs]
        if middle_round is not None:
            for r in list(range(initial_round - 1, middle_round)) + list(range(final_round, number_of_rounds)):
                all_components.extend([component.id for component in [*self._cipher.get_components_in_round(r)]])
            for r in list(range(initial_round - 1)) + list(range(middle_round - 1, final_round)):
                all_components.extend(['inverse_' + component.id for component in [*self.inverse_cipher.get_components_in_round(number_of_rounds - r - 1)]])
        else:
            for r in list(range(initial_round - 1, number_of_rounds)):
                all_components.extend([component.id for component in [*self._cipher.get_components_in_round(r)]])
            for r in list(range(final_round)):
                all_components.extend(['inverse_' + component.id for component in [*self.inverse_cipher.get_components_in_round(number_of_rounds - r - 1)]])
        all_components.extend(['inverse_' + id_link for id_link in [*self.inverse_cipher.inputs]])
        all_components.extend(['inverse_' + id_link for id_link in [*self._cipher.inputs]])
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

        return time, memory, components_values
            
    def set_inverse_component_id_in_constraints(self, component, inverse_variables, inverse_constraints):
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
        
        return inverse_variables, inverse_constraints

    def solve(self, model_type, solver_name=None, number_of_rounds=None, initial_round=None, middle_round=None, final_round=None, processes_=None, timeout_in_seconds_=None, all_solutions_=False, solve_external = False):
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        if final_round is None:
            final_round = self._cipher.number_of_rounds
        cipher_name = self.cipher_id
        input_file_path = f'{cipher_name}_Mzn_{model_type}_{solver_name}.mzn'
        command = self.get_command_for_solver_process(input_file_path, model_type, solver_name, processes_, timeout_in_seconds_)
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
                solve_time, memory, components_values = self._parse_solver_output(solver_output, number_of_rounds, initial_round, middle_round, final_round)
                total_weight = 0
            else:
                solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output, number_of_rounds, initial_round, middle_round, final_round)
            if components_values == {}:
                solution = convert_solver_solution_to_dictionary(self.cipher_id, model_type, solver_name,
                                                                 solve_time, memory,
                                                                 components_values, total_weight)
                if solver_output == []:
                    solution['status'] = 'UNSATISFIABLE'
                elif 'UNSATISFIABLE' in solver_output[0]:
                    solution['status'] = 'UNSATISFIABLE'
                else:
                    solution['status'] = 'SATISFIABLE'
                solutions.append(solution)
            else:
                self.add_solutions_from_components_values(components_values, memory, model_type, solutions, solve_time,
                                                          solver_name, solver_output, 0, solve_external)
            if model_type in ['xor_differential_one_solution',
                              'xor_linear_one_solution',
                              'deterministic_truncated_one_solution',
                              'impossible_xor_differential_one_solution']:
                return solutions[0]
            else:
                return solutions