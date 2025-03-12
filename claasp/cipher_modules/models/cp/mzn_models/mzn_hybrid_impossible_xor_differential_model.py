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
MZN Hybrid Impossible Xor Differential Model.

.. _mzn-hybrid-impossible-differential-standard:

MZN Hybrid Impossible XOR Differential
------------------------------------

The target of this class is to combine the precision of a bitwise impossible xor differential model while keeping track
of active non-linear components as done by the wordwise impossible xor differential model.
To do so, the domain of each variable is extended to include values that allow to identify in a unique way any active nonlinear
component.
"""

import ast
import itertools
import math
import os
import subprocess

from sage.combinat.permutation import Permutation
from sage.crypto.sbox import SBox

from claasp.cipher_modules.models.cp.mzn_model import solve_satisfy, MznModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_impossible_xor_differential_model import \
    MznImpossibleXorDifferentialModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import update_and_or_ddt_valid_probabilities
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary, check_if_implemented_component, \
    get_bit_bindings
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, SBOX, WORD_OPERATION,
                                  IMPOSSIBLE_XOR_DIFFERENTIAL, INPUT_PLAINTEXT, INPUT_KEY)


class MznHybridImpossibleXorDifferentialModel(MznImpossibleXorDifferentialModel):

    def __init__(self, cipher):
        super().__init__(cipher)
        self.sbox_size = None
        self.sboxes_component_number_list = {}
        self.sbox_ddt_values = []

    def build_hybrid_impossible_xor_differential_trail_model(
            self, fixed_variables=[], number_of_rounds=None,
            initial_round=1, middle_round=1, final_round=None, intermediate_components=True, probabilistic=True
    ):
        """
        Build the CP model for the search of hybrid impossible XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``number_of_rounds`` -- **integer** (default: `None`); number of rounds
        - ``initial_round`` -- **integer** (default: `1`); initial round of the differential
        - ``middle_round`` -- **integer** (default: `1`); inconsistency round of the differential
        - ``final_round`` -- **integer** (default: `None`); final round of the differential
        - ``intermediate_components`` -- **Boolean** (default: `True`); check inconsistency on intermediate components of the inconsistency round or only on outputs
        - ``probabilistic`` -- **Boolean** (default: `True`); allow probabilistic propagations for the key schedule, if any

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(speck)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
            sage: mzn.build_hybrid_impossible_xor_differential_trail_model(fixed_variables, 4, 1, 3, 4, False, False)
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

        if probabilistic:
            direct_variables, direct_constraints = self.build_improbable_forward_model(forward_components)
            inverse_variables, inverse_constraints = self.build_improbable_backward_model(backward_components,
                                                                                          clean=False)
        else:
            direct_variables, direct_constraints = self.build_impossible_forward_model(forward_components)
            inverse_variables, inverse_constraints = self.build_impossible_backward_model(backward_components,
                                                                                          clean=False)

        self._variables_list.extend(direct_variables)
        deterministic_truncated_xor_differential.extend(direct_constraints)

        inverse_variables, inverse_constraints = self.clean_inverse_impossible_variables_constraints(
            backward_components, inverse_variables, inverse_constraints
        )
        self._variables_list.extend(inverse_variables)
        deterministic_truncated_xor_differential.extend(inverse_constraints)

        variables, constraints = self.input_constraints(
            number_of_rounds=number_of_rounds, middle_round=middle_round, probabilistic=probabilistic
        )
        self._model_prefix.extend(variables)
        self._variables_list.extend(constraints)

        deterministic_truncated_xor_differential.extend(
            self.final_impossible_constraints(
                number_of_rounds, initial_round, middle_round, final_round,
                intermediate_components, probabilistic=probabilistic
            )
        )
        set_of_constraints = self._variables_list + deterministic_truncated_xor_differential

        self._model_constraints = self._model_prefix + self.clean_constraints(
            set_of_constraints, initial_round, middle_round, final_round
        )
    def build_improbable_forward_model(self, forward_components, clean=False):
        direct_variables = []
        direct_constraints = []
        key_components, key_ids = self.extract_key_schedule()
        for component in forward_components:
            if check_if_implemented_component(component):
                variables, constraints = self.propagate_deterministically(component,
                                                                          key_schedule=(component.id in key_ids),
                                                                          probabilistic=True)
                direct_variables.extend(variables)
                direct_constraints.extend(constraints)

        if clean:
            direct_variables, direct_constraints = self.clean_inverse_impossible_variables_constraints(
                forward_components, direct_variables, direct_constraints)

        return direct_variables, direct_constraints

    def build_improbable_backward_model(self, backward_components, clean=True):
        inverse_variables = []
        inverse_constraints = []
        key_components, key_ids = self.extract_key_schedule()
        constant_components, constant_ids = self.extract_constants()
        for component in backward_components:
            if check_if_implemented_component(component):
                variables, constraints = self.propagate_deterministically(component,
                                                                          key_schedule=(component.id in key_ids),
                                                                          inverse=True, probabilistic=True)
                inverse_variables.extend(variables)
                inverse_constraints.extend(constraints)

        if clean:
            components_to_invert = [backward_components[i] for i in range(len(backward_components))]
            for component in backward_components:
                for id_link in component.input_id_links:
                    input_component = self.get_component_from_id(id_link, self.inverse_cipher)
                    if input_component not in backward_components and id_link not in key_ids + constant_ids:
                        components_to_invert.append(input_component)
            inverse_variables, inverse_constraints = self.clean_inverse_impossible_variables_constraints_with_extensions(
                components_to_invert, inverse_variables, inverse_constraints)

        return inverse_variables, inverse_constraints

    def _extract_ones(self, matrix):
        result = []
        for row in matrix:
            if 1 in row:
                col_idx = row.index(1)
                result.append(col_idx)
        return result

    def _find_paths(self, graph, end_node, stop_at=INPUT_PLAINTEXT, path=None):
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
                    perm = Permutation([i + 1 for i in self._extract_ones(matrix)]).inverse()
                    P = [i - 1 for i in perm]
                    end_node = (end_node[0], str(P[int(end_node[-2])])) + ('i',)
                except Exception:
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

    def _output_is_aligned_with_sboxes(self, path_indices):
        for bit_positions in path_indices.values():
            if len(bit_positions ) <= 1:
                return True

            lst = sorted(bit_positions)
            for i in range(len(lst) - 1):
                if lst[i + 1] - lst[i] != 1:
                    return False
        return True

    def _generate_wordwise_incompatibility_constraint(self, component):

        if self.sbox_size:
            current_round = self._cipher.get_round_from_component_id(component.id)
            wordwise_incompatibility_constraint = ''

            single_round = self._cipher.remove_key_schedule().rounds.components_in_round(current_round)
            round_intermediate_output = [c for c in single_round if c.description == ['round_output']][0]
            graph = self._get_graph_for_round(self._cipher)
            path_indices = self._get_output_bits_connected_to_sboxes(round_intermediate_output, graph)

            if self._cipher.is_spn() or self._output_is_aligned_with_sboxes(path_indices):
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

    def final_impossible_constraints(self, number_of_rounds, initial_round, middle_round, final_round, intermediate_components, probabilistic=False):
        """
        Constraints for output and incompatibility.

        INPUT:

        - ``number_of_rounds`` -- **integer** ; number of rounds
        - ``initial_round`` -- **integer** ; initial round of the impossible differential trail
        - ``middle_round`` -- **integer** ; inconsistency round of the impossible differential trail
        - ``final_round`` -- **integer** ; final round of the impossible differential trail
        - ``intermediate_components`` -- **Boolean** ; check inconsistency on intermediate components of the inconsistency round or only on outputs
        - ``probabilistic`` -- **Boolean** (default: `True`); allow probabilistic propagations for the key schedule, if any

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: lblock = LBlockBlockCipher(number_of_rounds=3)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(lblock)
            sage: final = mzn.final_impossible_constraints(3, 1, 2, 3, False, False)
            sage: final[2]
            'output["plaintext = " ++ show(plaintext) ++ "\\n" ++ "inverse_key = " ++ show(inverse_key) ++ "\\n" ++ "inverse_cipher_output_2_19 = " ++ show(inverse_cipher_output_2_19) ++ "\\n" ++ "inverse_key = " ++ show(inverse_key) ++ "\\n" ++ "intermediate_output_0_0 = "++ show(intermediate_output_0_0)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_0_12 = "++ show(intermediate_output_0_12)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_0_18 = "++ show(intermediate_output_0_18)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_0 = "++ show(intermediate_output_1_0)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_1_0 = "++ show(inverse_intermediate_output_1_0)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_12 = "++ show(intermediate_output_1_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_1_12 = "++ show(inverse_intermediate_output_1_12)++ "\\n" ++ "0" ++ "\\n" ++"intermediate_output_1_18 = "++ show(intermediate_output_1_18)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_1_18 = "++ show(inverse_intermediate_output_1_18)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_0 = "++ show(inverse_intermediate_output_2_0)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_12 = "++ show(inverse_intermediate_output_2_12)++ "\\n" ++ "0" ++ "\\n" ++"inverse_intermediate_output_2_18 = "++ show(inverse_intermediate_output_2_18)++ "\\n" ++ "0" ++ "\\n" ++"inverse_cipher_output_2_19 = "++ show(inverse_cipher_output_2_19)++ "\\n" ++ "0" ++ "\\n" ];'


            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=3)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(present) #long# doctest: +SKIP
            sage: final = mzn.final_impossible_constraints(3, 1, 2, 3, False, False) #long# doctest: +SKIP
        """

        cipher_inputs = self._cipher.inputs if initial_round == 1 else ['key'] + [
            comp.id for comp in self._cipher.get_components_in_round(initial_round - 2) if 'output' in comp.id
        ]
        cipher = self._cipher
        cipher_outputs = self.inverse_cipher.inputs if final_round == self._cipher.number_of_rounds else ['key'] + [
            comp.id for comp in self.inverse_cipher.get_components_in_round(self._cipher.number_of_rounds - final_round)
            if 'output' in comp.id
        ]
        cp_constraints = [solve_satisfy]
        new_constraint = 'output['
        bitwise_incompatibility_constraint = ''
        wordwise_incompatibility_constraint = ''

        key_schedule_components, key_schedule_components_ids = self.extract_key_schedule()

        for element in cipher_inputs + cipher_outputs:
            prefix = "inverse_" if element in cipher_outputs else ""
            new_constraint += f'"{prefix}{element} = " ++ show({prefix}{element}) ++ "\\n" ++ '

        if probabilistic:
            new_constraint += '"Trail weight = " ++ show(weight) ++ "\\n" ++ "0" ++ "\\n" ++ '

        if intermediate_components:
            for component in cipher.get_components_in_round(middle_round - 1):
                if component.type != CONSTANT:
                    component_id = component.id
                    input_id_links = component.input_id_links
                    input_bit_positions = component.input_bit_positions
                    component_inputs = []
                    input_bit_size = 0
                    for id_link, bit_positions in zip(input_id_links, input_bit_positions):
                        component_inputs.extend([f'{id_link}[{position}]' for position in bit_positions])
                        input_bit_size += len(bit_positions)
                    for i in range(input_bit_size):
                        bitwise_incompatibility_constraint += f'({component_inputs[i]}+inverse_{component_id}[{i}]=1) \\/ '
                    wordwise_incompatibility_constraint += f'({self._generate_wordwise_incompatibility_constraint(component)}) \\/ '
                    if not probabilistic or component.type in [CIPHER_OUTPUT, INTERMEDIATE_OUTPUT]:
                        for id_link in input_id_links:
                            new_constraint = new_constraint + \
                                                 f'\"{id_link} = \"++ show({id_link})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                        new_constraint = new_constraint + \
                                             f'\"inverse_{component_id} = \"++ show(inverse_{component_id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'

        else:
            for component in cipher.get_all_components():
                extra_condition = (component.id in key_schedule_components_ids and component.description == ['round_key_output']) if probabilistic else True
                if 'output' in component.id:
                    if self.get_component_round(component.id) <= middle_round - 1 and extra_condition:
                        new_constraint = new_constraint + \
                                         f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    if self.get_component_round(component.id) >= middle_round - 1 and extra_condition:
                        new_constraint = new_constraint + \
                                         f'\"inverse_{component.id} = \"++ show(inverse_{component.id})++ \"\\n\" ++ \"0\" ++ \"\\n\" ++'
                    if self.get_component_round(
                            component.id) == middle_round - 1 and component.id not in key_schedule_components_ids and component.description == [
                        'round_output']:
                        for i in range(component.output_bit_size):
                            bitwise_incompatibility_constraint += f'({component.id}[{i}]+inverse_{component.id}[{i}]=1) \\/ '
                        wordwise_incompatibility_constraint += self._generate_wordwise_incompatibility_constraint(
                            component)
        bitwise_incompatibility_constraint = bitwise_incompatibility_constraint[:-4]
        new_constraint = new_constraint[:-2] + '];'
        wordwise_incompatibility_constraint = wordwise_incompatibility_constraint.rstrip(' \\/ ')
        cp_constraints.append(f"constraint ({bitwise_incompatibility_constraint}) \\/ ({wordwise_incompatibility_constraint});")
        cp_constraints.append(new_constraint)

        return cp_constraints

    def find_all_impossible_xor_differential_trails(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round = 1, middle_round=2, final_round = None, intermediate_components = True, probabilistic=False, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external = True):
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
        - ``probabilistic`` -- **Boolean** (default: `True`); allow probabilistic propagations for the key schedule, if any
        - ``num_of_processors`` -- **Integer** (default: `None`); number of processors used for MiniZinc search
        - ``timelimit`` -- **Integer** (default: `None`); time limit of MiniZinc search

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: lblock = LBlockBlockCipher(number_of_rounds=4)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(lblock)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(76), [0]*76)]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(64), [0]*64))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_3_19', 'equal', range(64), [0]*64))
            sage: trails = mzn.find_all_impossible_xor_differential_trails(4, fixed_variables, 'Chuffed', 1, 2, 4, intermediate_components=False)

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: lblock = LBlockBlockCipher(number_of_rounds=18)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(lblock) #long# doctest: +SKIP
            sage: fixed_variables = [set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80), bit_values=[0] * 49 + [1] + [0]*30)] #long# doctest: +SKIP
            sage: fixed_variables.append(set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions= range(64), bit_values= [0] * 60 + [1,0,0,0])) #long# doctest: +SKIP
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_17_19', 'equal', range(64), [0]*64)) #long# doctest: +SKIP
            sage: trails = mzn.find_all_impossible_xor_differential_trails(18, fixed_variables, 'Chuffed', 1, 9, 18, intermediate_components=False, probabilistic=True) #long# doctest: +SKIP
            sage: len(trails) #long# doctest: +SKIP
            6
            
        """
        self.build_hybrid_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components, probabilistic)

        if solve_with_API:
            return self.solve_for_ARX(solver_name=solver_name, timeout_in_seconds_=timelimit, processes_=num_of_processors, all_solutions_=True)
        return self.solve(IMPOSSIBLE_XOR_DIFFERENTIAL, solver_name=solver_name, number_of_rounds=number_of_rounds, initial_round=initial_round, middle_round=middle_round, final_round=final_round, timeout_in_seconds_=timelimit, processes_=num_of_processors, all_solutions_=True, solve_external=solve_external,  probabilistic=probabilistic)

    def find_one_impossible_xor_differential_trail(self, number_of_rounds=None, fixed_values=[], solver_name=None, initial_round=1, middle_round=2, final_round=None, intermediate_components=True, probabilistic=False, num_of_processors=None, timelimit=None, solve_with_API=False, solve_external=True):
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
        - ``probabilistic`` -- **Boolean** (default: `True`); allow probabilistic propagations for the key schedule, if any
        - ``num_of_processors`` -- **Integer** (default: `None`); number of processors used for MiniZinc search
        - ``timelimit`` -- **Integer** (default: `None`); time limit of MiniZinc search

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: lblock = LBlockBlockCipher(number_of_rounds=4)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(lblock)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(80), [0]*10+[1]+[0]*69)]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(64), [0]*64))
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_3_19', 'equal', range(64), [0]*64))
            sage: trail = mzn.find_one_impossible_xor_differential_trail(4, fixed_variables, 'Chuffed', 1, 2, 4, intermediate_components=False)

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hybrid_impossible_xor_differential_model import MznHybridImpossibleXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: lblock = LBlockBlockCipher(number_of_rounds=16)
            sage: mzn = MznHybridImpossibleXorDifferentialModel(lblock) #long# doctest: +SKIP
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(80), integer_to_bit_list(0x800, 80, 'big'))] #long# doctest: +SKIP
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'equal', range(64), [0]*64)) #long# doctest: +SKIP
            sage: fixed_variables.append(set_fixed_variables('inverse_cipher_output_15_19', 'equal', range(64), [0]*64)) #long# doctest: +SKIP
            sage: trail = mzn.find_one_impossible_xor_differential_trail(16, fixed_variables, 'Chuffed', 1, 8, 16, intermediate_components=False) #long# doctest: +SKIP
            ...

        """
        self.build_hybrid_impossible_xor_differential_trail_model(fixed_values, number_of_rounds, initial_round, middle_round, final_round, intermediate_components, probabilistic)
        
        if solve_with_API:
            return self.solve_for_ARX(solver_name=solver_name, timeout_in_seconds_=timelimit, processes_=num_of_processors)
        return self.solve('impossible_xor_differential_one_solution', solver_name=solver_name, number_of_rounds=number_of_rounds, initial_round=initial_round, middle_round=middle_round, final_round=final_round, timeout_in_seconds_=timelimit, processes_=num_of_processors, solve_external=solve_external,  probabilistic=probabilistic)

    def _get_sbox_max(self):
        nb_sbox = len([c for c in self._cipher.get_all_components() if c.type == SBOX])
        return 100*self._cipher.number_of_rounds + nb_sbox*10

    def input_constraints(self, number_of_rounds=None, middle_round=None, probabilistic=False):
        if number_of_rounds is None:
            number_of_rounds = self._cipher.number_of_rounds

        key_components, key_ids = self.extract_key_schedule()
        sbox_max = self._get_sbox_max()
        cp_constraints = []
        cp_declarations = [f"set of int: ext_domain = 0..2 union {{ i | i in 10..{sbox_max} where (i mod 10 = 0)}};"]
        cp_declarations += [
            f'array[0..{bit_size - 1}] of var ext_domain: {input_};'
            for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)
        ]

        inverse_cipher = self.inverse_cipher
        forward_components = []
        for r in range(middle_round):
            forward_components.extend(self._cipher.get_components_in_round(r))
        backward_components = []
        for r in range(number_of_rounds - middle_round + 1):
            backward_components.extend(inverse_cipher.get_components_in_round(r))

        cp_declarations.extend([
            f'array[0..{bit_size - 1}] of var ext_domain: inverse_{input_};'
            for input_, bit_size in zip(inverse_cipher.inputs, inverse_cipher.inputs_bit_size)
        ])

        prob_count = 0
        valid_probabilities = {0} if probabilistic else set()
        and_already_added = []

        for component in forward_components + backward_components:
            output_id_link = component.id
            output_size = int(component.output_bit_size)
            is_forward = component in forward_components
            prefix = "" if is_forward else "inverse_"

            if component.id in key_ids and SBOX in component.type and probabilistic:
                prob_count += 1
                self.update_sbox_ddt_valid_probabilities(component, valid_probabilities)
                cp_declarations.append(f'array[0..{output_size - 1}] of var 0..1: {prefix}{output_id_link};')
            elif component in key_components and WORD_OPERATION in component.type:
                if probabilistic:
                    if "AND" in component.description[0] or component.description[0] == "OR":
                        prob_count += component.description[1] * component.output_bit_size
                        update_and_or_ddt_valid_probabilities(and_already_added, component, cp_declarations,
                                                              valid_probabilities)
                    elif "MODADD" in component.description[0]:
                        prob_count += component.description[1] - 1
                        valid_probabilities |= set(range(100 * output_size)[::100])
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {prefix}{output_id_link};')
            elif "output" in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {prefix}{output_id_link};')
            elif CIPHER_OUTPUT in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {prefix}{output_id_link};')
                cp_constraints.append(f'constraint count({prefix}{output_id_link},2) < {output_size};')
                if not is_forward and not probabilistic:
                    cp_constraints.append(f'constraint count({prefix}{output_id_link},1) > 0;')
            elif CONSTANT not in component.type:
                cp_declarations.append(f'array[0..{output_size - 1}] of var ext_domain: {prefix}{output_id_link};')

        if INPUT_KEY in self._cipher.inputs:
            cp_constraints.append("constraint inverse_key = key;")
        for input_id, input_size in self._cipher.inputs_size_to_dict().items():
            cp_constraints.append(f'constraint forall (i in 0..{input_size-1})({input_id}[i] <= 2);')

        cp_constraints.append(f"constraint count({' ++ '.join(self._cipher.inputs)}, 1) > 0;")


        for component in key_components:
            if component.id in set(key_ids) & set(c.id for c in forward_components) & set(
                    c.id for c in backward_components):
                cp_declarations.append(f"constraint {component.id} = inverse_{component.id};")

        if probabilistic:
            cp_declarations_weight = 'int: weight = -1;'
            if prob_count > 0:
                self._probability = True
                last_round_key = [c for c in key_components if c.description == ["round_key_output"]][
                    number_of_rounds - 1].id
                prob_variables = f"array[0..{prob_count - 1}] of var {valid_probabilities}: p;"
                cp_declarations.append(prob_variables)
                cp_declarations_weight = f"var int: weight = p[{'] + p['.join(map(str, [val for c, val in self.component_and_probability.items() if key_ids.index(c) < key_ids.index(last_round_key)]))}];"
            cp_declarations.append(cp_declarations_weight)

        return cp_declarations, cp_constraints

    def propagate_deterministically(self, component, key_schedule=False, wordwise=False, inverse=False, probabilistic=False):
        if not wordwise:
            if component.type == SBOX:
                if key_schedule and probabilistic:
                    variables, constraints = component.cp_xor_differential_propagation_constraints(
                        self, inverse)
                else:
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

    def update_sbox_ddt_valid_probabilities(self, component, valid_probabilities):
        input_size = int(component.input_bit_size)
        output_id_link = component.id
        description = component.description
        sbox = SBox(description)
        sbox_already_in = False
        for mant in self.sbox_ddt_values:
            if description == mant[0]:
                sbox_already_in = True
        if not sbox_already_in:
            sbox_ddt = sbox.difference_distribution_table()
            for i in range(sbox_ddt.nrows()):
                set_of_occurrences = set(sbox_ddt.rows()[i])
                set_of_occurrences -= {0}
                valid_probabilities.update({round(100 * math.log2(2 ** input_size / occurrence))
                                            for occurrence in set_of_occurrences})
            self.sbox_ddt_values.append((description, output_id_link))

    def _parse_solver_output(self, output_to_parse, number_of_rounds, initial_round, middle_round, final_round, probabilistic=False):

        if probabilistic:
            components_values, memory, time, total_weight = self.parse_solver_information(output_to_parse, False, True)
        else:
            components_values, memory, time = self.parse_solver_information(output_to_parse, True, True)
            total_weight = [0] * len(components_values)

        all_components = [*self._cipher.inputs]
        for r in list(range(initial_round - 1, middle_round)) + list(range(final_round, number_of_rounds)):
            all_components.extend([component.id for component in [*self._cipher.get_components_in_round(r)]])
        for r in list(range(initial_round - 1)) + list(range(middle_round - 1, final_round)):
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

        return time, memory, components_values, total_weight

    def solve(self, model_type, solver_name=None, number_of_rounds=None, initial_round=None, middle_round=None, final_round=None, processes_=None, timeout_in_seconds_=None, all_solutions_=False, solve_external = False, probabilistic=False):
        cipher_name = self.cipher_id
        input_file_path = f'{cipher_name}_Mzn_{model_type}_{solver_name}.mzn'
        command = self.get_command_for_solver_process(input_file_path, model_type, solver_name, processes_, timeout_in_seconds_)
        solver_process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        os.remove(input_file_path)
        if solver_process.returncode >= 0:
            solutions = []
            solver_output = solver_process.stdout.splitlines()
            solve_time, memory, components_values, total_weight = self._parse_solver_output(solver_output, number_of_rounds, initial_round, middle_round, final_round, probabilistic)
            if probabilistic:
                weight_list = [int(float(x)) for x in total_weight]
                summed_weight = sum(2 ** (-x) for x in weight_list if x)
                cumulated_weight = math.log(summed_weight) / math.log(2) if summed_weight else 0
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
                MznModel.add_solutions_from_components_values(self, components_values, memory, model_type, solutions, solve_time,
                                                          solver_name, solver_output, total_weight, solve_external)
            if model_type in ['xor_differential_one_solution',
                              'xor_linear_one_solution',
                              'deterministic_truncated_one_solution',
                              'impossible_xor_differential_one_solution']:
                return solutions[0]
            if probabilistic:
                return {'total_weight': cumulated_weight, 'solutions': solutions}
            else:
                return solutions