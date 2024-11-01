import ast
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

from sage.combinat.permutation import Permutation

from claasp.cipher_modules.models.cp.mzn_model import solve_satisfy
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary, check_if_implemented_component
from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import \
    MznImpossibleXorDifferentialModel
from claasp.cipher_modules.models.utils import write_model_to_file, convert_solver_solution_to_dictionary, \
    check_if_implemented_component, get_bit_bindings

from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                                  WORD_OPERATION, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, IMPOSSIBLE_XOR_DIFFERENTIAL)
from claasp.cipher_modules.models.cp.solvers import CP_SOLVERS_EXTERNAL, SOLVER_DEFAULT


class MznHybridImpossibleXorDifferentialModel(MznImpossibleXorDifferentialModel):

    def __init__(self, cipher):
        super().__init__(cipher)
        self.sbox_size = None
        self.sboxes_component_number_list = {}

    
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

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznHybridImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: cp.build_impossible_xor_differential_trail_model(fixed_variables, 4, 1, 3, 4, False)
        """
        self.initialise_model()
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds
        if final_round is None:
            final_round = self._cipher.number_of_rounds
        inverse_cipher = self.inverse_cipher

        for r in range(self._cipher.number_of_rounds):
            self.sboxes_component_number_list[r] = []
        for component in filter(lambda c: c.type == SBOX, self.cipher.get_all_components()):
            round_num, component_num = map(int, component.id.split("_")[-2:])
            self.sboxes_component_number_list[round_num] += [component_num]

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

        inverse_variables, inverse_constraints = self.build_impossible_backward_model(backward_components, clean = False)
        inverse_variables, inverse_constraints = self.clean_inverse_impossible_variables_constraints(backward_components, inverse_variables, inverse_constraints)
        self._variables_list.extend(inverse_variables)
        deterministic_truncated_xor_differential.extend(inverse_constraints)

        variables, constraints = self.input_impossible_constraints(number_of_rounds = number_of_rounds, middle_round = middle_round)
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)
        deterministic_truncated_xor_differential.extend(self.final_impossible_constraints(number_of_rounds, initial_round, middle_round, final_round, intermediate_components))
        set_of_constraints = self._variables_list + deterministic_truncated_xor_differential
        
        self._model_constraints = self._model_prefix + self.clean_constraints(set_of_constraints, initial_round, middle_round, final_round)

    def extract_ones(self, matrix):
        result = []
        for row in matrix:
            if 1 in row:
                col_idx = row.index(1)
                result.append(col_idx)
        return result

    def _find_paths(self, graph, end_node, stop_at='plaintext', path=None):
        if path is None:
            path = []

        path = [end_node] + path
        end_node = end_node[:-1] + ('i',)

        # if permutation
        if end_node[0] != 'plaintext':
            component = self.cipher.get_component_from_id(end_node[0])
            if component.type == 'linear_layer':
                matrix = component.description
                try:
                    perm = Permutation([i + 1 for i in self.extract_ones(matrix)]).inverse()
                    P = [i - 1 for i in perm]
                    end_node = (end_node[0], str(P[int(end_node[-2])])) + ('i',)
                except ValueError:
                    pass

        if stop_at in end_node[0] or not any(end_node in neighbors for neighbors in graph.values()):
            return path

        for node, neighbors in graph.items():
            if end_node in neighbors:
                return self._find_paths(graph, node, stop_at, path)

        return path

    def _get_graph_for_round(self, cipher_round):
        bit_bindings, intermediate_bit_bindings = get_bit_bindings(cipher_round)
        for interm_binding in intermediate_bit_bindings.values():
            for key, value_list in interm_binding.items():
                filtered_values = [val for val in value_list if val[2] == 'o']
                for val in filtered_values:
                    related_values = [other_val for other_val in value_list if other_val != val]
                    bit_bindings[val] = bit_bindings.get(val, []) + [key] + related_values

        return bit_bindings

    def _get_output_bits_connected_to_sboxes(self, intermediate_output, graph):
        path_indices = {}
        for bit in range(intermediate_output.output_bit_size):
            path = self._find_paths(graph, (f'{intermediate_output.id}', f'{bit}', 'i'), stop_at=SBOX)
            if path[0][0] not in path_indices:
                path_indices[path[0][0]] = [int(path[-1][1])]
            else:
                path_indices[path[0][0]] += [int(path[-1][1])]
        return path_indices

    def output_is_aligned_with_sboxes(self, path_indices):
        for bit_positions in path_indices.values():
            if len(bit_positions ) <= 1:
                return True

            lst = sorted(bit_positions)
            for i in range(len(lst) - 1):
                if lst[i + 1] - lst[i] != 1:
                    return False
        return True

    def _generate_wordwise_incompatibility_constraint(self, component):
        self.sbox_size = 4

        if self.sbox_size:
            current_round = self._cipher.get_round_from_component_id(component.id)
            wordwise_incompatibility_constraint = ''

            single_round = self._cipher.remove_key_schedule().rounds.components_in_round(current_round)
            round_intermediate_output = [c for c in single_round if c.description == ['round_output']][0]
            graph = self._get_graph_for_round(self._cipher)
            path_indices = self._get_output_bits_connected_to_sboxes(round_intermediate_output, graph)

            if self._cipher.is_spn() or self.output_is_aligned_with_sboxes(path_indices):
                intermediate_output_bit_positions = path_indices.values()
            else:
                intermediate_output_bit_positions = itertools.combinations(range(len(path_indices.keys()) * self.sbox_size), self.sbox_size)

            for bit_positions, suffix in itertools.product(intermediate_output_bit_positions, ['', 'inverse_']):
                constraint = '('
                constraint += '/\\'.join(
                    [f'({component.id}[{i}]+inverse_{component.id}[{i}]={suffix + component.id}[{i}])' for i in
                     bit_positions])
                constraint += '/\\' + '/\\'.join([f'({suffix + component.id}[{i}] > 2)' for i in bit_positions])
                constraint += '/\\' + '/\\'.join(
                    [f'({suffix + component.id}[{i}] = {suffix + component.id}[{bit_positions[0]}])' for i in
                     bit_positions[1:]])
                wordwise_incompatibility_constraint += constraint + ') \\/'
            return wordwise_incompatibility_constraint[:-3]
        else:
            return 'False'
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

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=5)
            sage: cp = MznHybridImpossibleXorDifferentialModel(speck)
            sage: cp.final_impossible_constraints(3, 2, 3, 4, False)
            ['solve satisfy;',
             ...
             'output["key = "++ show(key) ++ "\\n" ++"intermediate_output_0_5 = "++ show(intermediate_output_0_5) ++ "\\n" ++"intermediate_output_0_6 = "++ show(intermediate_output_0_6) ++ "\\n" ++"inverse_key = "++ show(inverse_key) ++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_3_12 = "++ show(inverse_intermediate_output_3_12) ++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_0_6 = "++ show(intermediate_output_0_6)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_12 = "++ show(intermediate_output_1_12)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_2_12 = "++ show(intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_12 = "++ show(inverse_intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_3_12 = "++ show(inverse_intermediate_output_3_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_cipher_output_4_12 = "++ show(inverse_cipher_output_4_12)++ "\\n" ++ "0" ++ "\\n" ];']

             sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
             sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
             sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
             sage: lblock = LBlockBlockCipher(number_of_rounds=3)
             sage: cp = MznHybridImpossibleXorDifferentialModel(lblock)
             sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0x800, 64, 'big'))]
             sage: final = cp.final_impossible_constraints(3,1, 2, 3, False)

             sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
             sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
             sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
             sage: present = PresentBlockCipher(number_of_rounds=3)
             sage: cp = MznHybridImpossibleXorDifferentialModel(present)
             sage: final = cp.final_impossible_constraints(3,1, 2, 3, False)
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
        bitwise_incompatibility_constraint = ''
        wordwise_incompatibility_constraint = ''

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
                        bitwise_incompatibility_constraint += f'({component_inputs[i]}+inverse_{component_id}[{i}]=1) \\/ '
        else:
            for component in cipher.get_all_components():
                if 'output' in component.id and component.id not in key_schedule_components_ids:
                    if self.get_component_round(component.id) <= middle_round - 1:
                        new_constraint = new_constraint + \
                        f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    if self.get_component_round(component.id) >= middle_round - 1:
                        new_constraint = new_constraint + \
                        f'\"inverse_{component.id} = \"++ show(inverse_{component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    if self.get_component_round(component.id) == middle_round - 1 and component.id not in key_schedule_components_ids:
                        for i in range(component.output_bit_size):
                            bitwise_incompatibility_constraint += f'({component.id}[{i}]+inverse_{component.id}[{i}]=1) \\/ '
                        wordwise_incompatibility_constraint += self._generate_wordwise_incompatibility_constraint(component)
        bitwise_incompatibility_constraint = bitwise_incompatibility_constraint[:-4]
        new_constraint = new_constraint[:-2] + '];'
        cp_constraints.append(f'constraint ({bitwise_incompatibility_constraint}) \\/ ({wordwise_incompatibility_constraint});')
        cp_constraints.append(new_constraint)

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

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznHybridImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_3_12', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little')))
            sage: trail = cp.find_all_impossible_xor_differential_trails(4, fixed_variables, 'Chuffed', 1, 3, 4, False) #doctest: +SKIP
            
        """
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)

        if solve_with_API:
            return self.solve_for_ARX(solver_name=solver_name, timeout_in_seconds_=timelimit, processes_=num_of_processors, all_solutions_=True)
        return self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name, number_of_rounds=number_of_rounds, initial_round=initial_round, middle_round=middle_round, final_round=final_round, timeout_in_seconds_=timelimit, processes_=num_of_processors, all_solutions_=True, solve_external=solve_external)

    def find_one_impossible_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round=1, middle_round=2, final_round=None, intermediate_components=True, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external=True):
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

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: lblock = LBlockBlockCipher(number_of_rounds=16)
            sage: cp = MznHybridImpossibleXorDifferentialModel(lblock)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(80), integer_to_bit_list(0x800, 80, 'big'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(64), [0]*64))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_15_19', 'equal', range(64), [0]*64))
            sage: trail = cp.find_one_impossible_xor_differential_trail(16, fixed_variables, 'Chuffed', 1, 8, 16, intermediate_components=False)

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: lblock = LBlockBlockCipher(number_of_rounds=3)
            sage: cp = MznHybridImpossibleXorDifferentialModel(lblock)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(80), [0]*10+[1]+[0]*69)]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(64), [0]*64))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_2_19', 'equal', range(64), [0]*64))
            sage: trail = cp.find_one_impossible_xor_differential_trail(3, fixed_variables, 'Chuffed', 1, 2, 3, intermediate_components=False)

        """
        self.build_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components)
        
        if solve_with_API:
            return self.solve_for_ARX(solver_name=solver_name, timeout_in_seconds_=timelimit, processes_=num_of_processors)
        return self.solve('impossible_xor_differential_one_solution', solver_name=solver_name, number_of_rounds=number_of_rounds, initial_round=initial_round, middle_round=middle_round, final_round=final_round, timeout_in_seconds_=timelimit, processes_=num_of_processors, solve_external=solve_external)

    def _get_sbox_max(self):
        nb_sbox = len([c for c in self._cipher.get_all_components() if c.type == SBOX])
        return 100*self._cipher.number_of_rounds + nb_sbox*10

    def input_impossible_constraints(self, number_of_rounds=None, middle_round=None):

        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        sbox_max = self._get_sbox_max()
        cp_constraints = []
        cp_declarations = [f"set of int: ext_domain = 0..2 union {{ i | i in 10..{sbox_max} where (i mod 10 = 0)}};"]
        cp_declarations += [f'array[0..{bit_size - 1}] of var ext_domain: {input_};'
                            for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        cipher = self._cipher
        inverse_cipher = self.inverse_cipher
        forward_components = []
        for r in range(middle_round):
            forward_components.extend(self._cipher.get_components_in_round(r))
        backward_components = []
        for r in range(number_of_rounds - middle_round + 1):
            backward_components.extend(inverse_cipher.get_components_in_round(r))
        cp_declarations.extend([f'array[0..{bit_size - 1}] of var ext_domain: inverse_{input_};' for input_, bit_size in zip(inverse_cipher.inputs, inverse_cipher.inputs_bit_size)])
        for component in forward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {output_id_link};')
                cp_constraints.append(f'constraint count({output_id_link},2) < {output_size};')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {output_id_link};')
        for component in backward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            if 'output' in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: inverse_{output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: inverse_{output_id_link};')
                cp_constraints.append(f'constraint count(inverse_{output_id_link},2) < {output_size};')
                cp_constraints.append(f'constraint count(inverse_{output_id_link},1) > 0;')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: inverse_{output_id_link};')
        cp_constraints.append('constraint count(plaintext,1) >= 0;')
        cp_constraints.append('constraint inverse_key = key;')

        return cp_declarations, cp_constraints

    def propagate_deterministically(self, component, wordwise=False, inverse=False):
        if not wordwise:
            if component.type == SBOX:
                variables, constraints, sbox_mant = component.cp_hybrid_deterministic_truncated_xor_differential_constraints(
                    self.sbox_mant, inverse, self.sboxes_component_number_list)
                self.sbox_mant = sbox_mant
                self.sbox_size = component.output_bit_size
            elif component.description[0] == 'XOR':
                variables, constraints = component.cp_hybrid_deterministic_truncated_xor_differential_constraints()
            else:
                variables, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
        else:
            variables, constraints = component.cp_wordwise_deterministic_truncated_xor_differential_constraints(self)

        return variables, constraints

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
                inverse_constraints[c] = inverse_constraints[c][:new_start] + 'inverse_' + inverse_constraints[c][
                                                                                           new_start:]
                start = new_start + 9

        return inverse_variables, inverse_constraints

    def format_component_value(self, component_id, string):
        if f'{component_id}_i' in string:
            value = string.replace(f'{component_id}_i', '')
        elif f'{component_id}_o' in string:
            value = string.replace(f'{component_id}_o', '')
        elif f'inverse_{component_id}' in string:
            value = string.replace(f'inverse_{component_id}', '')
        elif f'{component_id}' in string:
            value = string.replace(component_id, '')
        value = ['.' if x == 0 else str(x) if x < 2 else '?' if x == 2 else str(x % 7) for x in ast.literal_eval(value[3:])]

        return ''.join(value)