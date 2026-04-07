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

from claasp.cipher_modules.models.cp.mzn_model import MznModel, solve_satisfy
from claasp.cipher_modules.models.sat.utils.utils import _generate_component_model_types, _set_model_type_for_components
from claasp.name_mappings import SBOX, CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, WORD_OPERATION
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_bct_predicates import get_bct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_lbct_predicates import get_lbct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_ubct_predicates import get_ubct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_ebct_predicates import get_ebct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_ubct_predicate import get_evaluation_ubct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_lbct_predicate import get_evaluation_lbct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_evaluation_ebct_predicate import get_evaluation_ebct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_approx_logarithm_predicate import get_approx_logarithm_operation_lower_bound, get_approx_logarithm_operation_upper_bound
from copy import deepcopy
import math
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import update_and_or_ddt_valid_probabilities
from sage.crypto.sbox import SBox

class MznHadipourBoomerangModel(MznModel):
    def __init__(self, cipher, boomerang_structure):
        self.boomerang_structure = boomerang_structure
        self.top_part_number_of_rounds = boomerang_structure["top_part_number_of_rounds"]
        self.middle_part_number_of_rounds = boomerang_structure["middle_part_number_of_rounds"]
        self.bottom_part_number_of_rounds = boomerang_structure["bottom_part_number_of_rounds"]

        total_number_of_rounds = self.top_part_number_of_rounds + self.middle_part_number_of_rounds + self.bottom_part_number_of_rounds
        assert total_number_of_rounds == cipher.number_of_rounds

        e0em_cipher = cipher.get_partial_cipher(
            start_round=0,
            end_round=self.top_part_number_of_rounds + self.middle_part_number_of_rounds - 1,
            keep_key_schedule=False
        )
        
        e0em_cipher.add_prefix('upper_')
        
        eme1_cipher = cipher.cipher_partial_inverse(
            start_round=self.top_part_number_of_rounds,
            end_round=self.top_part_number_of_rounds + self.middle_part_number_of_rounds + self.bottom_part_number_of_rounds - 1,
            keep_key_schedule=False
        )

        eme1_cipher.add_prefix('lower_')
        
        for i in range(0, self.middle_part_number_of_rounds):
            e0em_cipher._rounds.rounds[self.top_part_number_of_rounds + i]._components.extend(eme1_cipher._rounds.rounds[self.bottom_part_number_of_rounds +
                                                                                                                        self.middle_part_number_of_rounds -i -1]._components)        
        ## add also the last part of e1
        for i in range(0, self.bottom_part_number_of_rounds):
            e0em_cipher._rounds.rounds[self.top_part_number_of_rounds + self.middle_part_number_of_rounds + i]._components.extend(eme1_cipher._rounds.rounds[self.bottom_part_number_of_rounds 
                                                                                                                                                             - i - 1]._components)
        e0em_cipher.inputs.extend(eme1_cipher.inputs)
        e0em_cipher.inputs_bit_size.extend(eme1_cipher.inputs_bit_size)

        unified_cipher = e0em_cipher

        self._first_step = []
        self._first_step_find_all_solutions = []
        self._cp_xor_differential_constraints = []

        super().__init__(unified_cipher)

    def input_xor_differential_constraints(self):
        """
        Return a list of CP declarations and a list of Cp constraints for the first part of the xor differential model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import (MznXorDifferentialModel)
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorDifferentialModel(speck)
            sage: cp.input_xor_differential_constraints()
            (['array[0..31] of var 0..1: plaintext;',
              'array[0..63] of var 0..1: key;',
               ...
              'array[0..31] of var 0..1: cipher_output_3_12;',
              'array[0..6] of var {0, 900, 200, 1100, 400, 1300, 600, 1500, 800, 100, 1000, 300, 1200, 500, 1400, 700}: p;',
              'var int: weight = sum(p);'],
             [])
        """
        
        self._cp_xor_differential_constraints = [f'array[0..{bit_size - 1}] of var 0..1: {input_};'
                           for input_, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size)]
        
        self.sbox_mant = []
        prob_count_upper = 0
        prob_count_lower = 0
        valid_probabilities_upper = {0}
        valid_probabilities_lower = {0}
        and_already_added_upper = []
        and_already_added_lower = []
        
        for component in self._cipher.get_all_components():
            if CONSTANT not in component.type:
                output_id_link = component.id
                app = f'array[0..{int(component.output_bit_size) - 1}] of var 0..1: {output_id_link};'
                if app not in self._cp_xor_differential_constraints and app not in self._model_constraints:
                    self._cp_xor_differential_constraints.append(f'array[0..{int(component.output_bit_size) - 1}] of var 0..1: {output_id_link};')
                if SBOX in component.type:
                    if 'upper_' in component.id:
                        prob_count_upper += 1
                        self.update_sbox_ddt_valid_probabilities(component, valid_probabilities_upper)
                    elif 'lower_' in component.id:
                        prob_count_lower += 1
                        self.update_sbox_ddt_valid_probabilities(component, valid_probabilities_lower)
                elif WORD_OPERATION in component.type:
                    if 'AND' in component.description[0] or component.description[0] == 'OR':
                        if 'upper_' in component.id:
                            prob_count_upper += component.description[1] * component.output_bit_size
                            update_and_or_ddt_valid_probabilities(and_already_added_upper, component, self._cp_xor_differential_constraints,
                                                          valid_probabilities_upper)
                        elif 'lower_' in component.id:
                            prob_count_lower += component.description[1] * component.output_bit_size
                            update_and_or_ddt_valid_probabilities(and_already_added_lower, component, self._cp_xor_differential_constraints,
                                                          valid_probabilities_lower)
                    elif 'MODADD' in component.description[0]:
                        prob_count_upper += component.description[1] - 1
                        output_size = component.output_bit_size
                        valid_probabilities_upper |= set(range(100 * output_size)[::100])
                    elif 'MODSUB' in component.description[0]:
                        prob_count_lower += component.description[1] - 1
                        output_size = component.output_bit_size
                        valid_probabilities_lower |= set(range(100 * output_size)[::100])

        upper_keys = [key.removeprefix('upper_') for key in self.component_and_probability.keys() if 'upper_' in key]
        lower_keys = [key.removeprefix('lower_') for key in self.component_and_probability.keys() if 'lower_' in key]
        
        middle_keys = list(set(upper_keys) & set(lower_keys)) ## non linear year id just in Em
        just_upper_keys = ['upper_' + key for key in upper_keys if key not in middle_keys] ## non linear layer id just in E0
        just_lower_keys = ['lower_' + key for key in lower_keys if key not in middle_keys] ## non linear layer id just in E1
        
        total_declatation_of_p = f'array[0..{len(just_upper_keys) + len(just_lower_keys) + len(middle_keys)}-1] of var int: p;'
        self._cp_xor_differential_constraints.append(total_declatation_of_p)

        count_index_for_assign_p_with_upper_lower_middle_p = 0

        cp_declarations_weight_upper = 'int: upper_weight = 0;'
        if prob_count_upper > 0:
            new_declaration_upper = f'array[0..{prob_count_upper}-1] of var {valid_probabilities_upper}: upper_p;'
            self._cp_xor_differential_constraints.append(new_declaration_upper)
            if self.top_part_number_of_rounds > 0:
                cp_declarations_weight_upper = 'var int: upper_weight ='
                for key in just_upper_keys:
                    cp_declarations_weight_upper += f' upper_p[{self.component_and_probability[key][0]}] +'
                    contrains_of_p_upper = f'constraint p[{count_index_for_assign_p_with_upper_lower_middle_p}] = upper_p[{self.component_and_probability[key][0]}];'
                    self._cp_xor_differential_constraints.append(contrains_of_p_upper)
                    count_index_for_assign_p_with_upper_lower_middle_p += 1
                cp_declarations_weight_upper = cp_declarations_weight_upper[:-2] + ';'
                
        self._cp_xor_differential_constraints.append(cp_declarations_weight_upper)

        cp_declarations_weight_lower = 'int: lower_weight = 0;'
        if prob_count_lower > 0:
            new_declaration_lower = f'array[0..{prob_count_lower}-1] of var {valid_probabilities_lower}: lower_p;'
            self._cp_xor_differential_constraints.append(new_declaration_lower)
            if self.bottom_part_number_of_rounds > 0:
                cp_declarations_weight_lower = 'var int: lower_weight ='
                for key in just_lower_keys:
                    cp_declarations_weight_lower += f' lower_p[{self.component_and_probability[key][0]}] +'
                    contrains_of_p_lower = f'constraint p[{count_index_for_assign_p_with_upper_lower_middle_p}] = lower_p[{self.component_and_probability[key][0]}];'
                    self._cp_xor_differential_constraints.append(contrains_of_p_lower)
                    count_index_for_assign_p_with_upper_lower_middle_p += 1
                cp_declarations_weight_lower.removesuffix(' +')
                cp_declarations_weight_lower = cp_declarations_weight_lower[:-2] + ';'
                
        self._cp_xor_differential_constraints.append(cp_declarations_weight_lower)

        new_declaration_middle = f'array[0..{len(middle_keys)}-1] of var 0..3200: middle_p;'
        self._cp_xor_differential_constraints.append(new_declaration_middle)
        new_declaration_middle = f'array[0..{len(middle_keys)}-1] of var 0..3200: upper_bound_middle_p;'
        self._cp_xor_differential_constraints.append(new_declaration_middle)

        self.count_middle_p = 0
        self.count_index_for_assign_p_with_upper_lower_middle_p = count_index_for_assign_p_with_upper_lower_middle_p

        if self.middle_part_number_of_rounds == 1:
            for middle_non_linear_transition_ids in middle_keys:
                deltaL, deltaR, nablaL, nablaR, _, _, branch_size = self.addSwitch(middle_non_linear_transition_ids)
                self._model_constraints.extend(MznHadipourBoomerangModel.bct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, branch_size))
        else:
            vals = [int(s.split('_')[1]) for s in middle_keys]
            mn, mx = min(vals), max(vals)

            list_ubct_middle_keys, list_ebct_middle_keys, list_lbct_middle_keys = (
                [s for s in middle_keys if int(s.split('_')[1]) == mn],
                [s for s in middle_keys if mn < int(s.split('_')[1]) < mx],
                [s for s in middle_keys if int(s.split('_')[1]) == mx],
            )
            
            for middle_non_linear_transition_ids in list_ubct_middle_keys:
                deltaL, deltaR, nablaL, nablaR, deltaLL, _, branch_size = self.addSwitch(middle_non_linear_transition_ids)
                self._model_constraints.extend(MznHadipourBoomerangModel.ubct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, deltaLL, branch_size))
                self._model_constraints.extend(MznHadipourBoomerangModel.evaluation_ubct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, deltaLL, branch_size, self.count_middle_p-1))

            if self.middle_part_number_of_rounds > 2:       
                for middle_non_linear_transition_ids in list_ebct_middle_keys:
                    deltaL, deltaR, nablaL, nablaR, deltaLL, nablaLL, branch_size = self.addSwitch(middle_non_linear_transition_ids)
                    self._model_constraints.extend(MznHadipourBoomerangModel.ebct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, deltaLL, nablaLL, branch_size))
                    self._model_constraints.extend(MznHadipourBoomerangModel.evaluation_ebct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, deltaLL, nablaLL, branch_size, self.count_middle_p-1))

            for middle_non_linear_transition_ids in list_lbct_middle_keys:
                deltaL, deltaR, nablaL, nablaR, _, nablaLL, branch_size = self.addSwitch(middle_non_linear_transition_ids)
                self._model_constraints.extend(MznHadipourBoomerangModel.lbct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, nablaLL, branch_size))
                self._model_constraints.extend(MznHadipourBoomerangModel.evaluation_lbct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, nablaLL, branch_size, self.count_middle_p-1))

            self.branch_size = branch_size

        cp_declarations_weight_middle = 'var int: middle_weight = sum(middle_p);'
        self._cp_xor_differential_constraints.append(cp_declarations_weight_middle)
        cp_declarations_weight_middle = 'var int: upper_bound_middle_weight = sum(upper_bound_middle_p);'
        self._cp_xor_differential_constraints.append(cp_declarations_weight_middle)

        new_declaration = 'var int: weight = (2 * upper_weight) + (2 * lower_weight) + middle_weight;'
        self._cp_xor_differential_constraints.append(new_declaration)
        new_declaration = 'var int: upper_bound_weight = (2 * upper_weight) + (2 * lower_weight) + upper_bound_middle_weight;'
        self._cp_xor_differential_constraints.append(new_declaration)

        variables = []
        return variables, self._cp_xor_differential_constraints
    
    def addSwitch(self, middle_non_linear_transition_ids):
        self.component_and_probability['middle_' + middle_non_linear_transition_ids] = [self.count_middle_p]
        middle_non_linear_transition_ids_up = 'upper_' + middle_non_linear_transition_ids
        middle_non_linear_transition_ids_lo = 'lower_' + middle_non_linear_transition_ids
        contrains_of_p_middle = f'constraint p[{self.count_index_for_assign_p_with_upper_lower_middle_p}] = middle_p[{self.count_middle_p}];'         
        self._cp_xor_differential_constraints.append(contrains_of_p_middle)
    
        deltaL = 'pre_' + middle_non_linear_transition_ids_up + '_0'
        deltaR = 'pre_' + middle_non_linear_transition_ids_up + '_1'
        nablaL = 'pre_' + middle_non_linear_transition_ids_lo + '_0'
        nablaR = 'pre_' + middle_non_linear_transition_ids_lo + '_1'
        deltaLL = middle_non_linear_transition_ids_up
        nablaLL = middle_non_linear_transition_ids_lo
        branch_size = self.cipher.get_component_from_id(middle_non_linear_transition_ids_up).output_bit_size
        self.count_middle_p += 1
        self.count_index_for_assign_p_with_upper_lower_middle_p += 1

        return deltaL, deltaR, nablaL, nablaR, deltaLL, nablaLL, branch_size

    def update_sbox_ddt_valid_probabilities(self, component, valid_probabilities):
        input_size = int(component.input_bit_size)
        output_id_link = component.id
        description = component.description
        sbox = SBox(description)
        sbox_already_in = False
        for mant in self.sbox_mant:
            if description == mant[0]:
                sbox_already_in = True
        if not sbox_already_in:
            sbox_ddt = sbox.difference_distribution_table()
            for i in range(sbox_ddt.nrows()):
                set_of_occurrences = set(sbox_ddt.rows()[i])
                set_of_occurrences -= {0}
                valid_probabilities.update({round(100 * math.log2(2 ** input_size / occurrence))
                                            for occurrence in set_of_occurrences})
            self.sbox_mant.append((description, output_id_link))


    def final_xor_differential_constraints(self, weight, milp_modadd = False):
        """
        Return a CP constraints list for the cipher outputs and solving indications for single or second step model.

        INPUT:

        - ``weight`` -- **integer**; a specific weight. If set to non-negative integer, fixes the XOR trail weight

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import (MznXorDifferentialModel)
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
            sage: cp = MznXorDifferentialModel(speck)
            sage: cp.build_xor_differential_trail_model(-1)
            sage: cp.final_xor_differential_constraints(-1)[:-1]
            ['solve:: int_search(p, smallest, indomain_min, complete) minimize weight;']
        """
        cipher_inputs = self._cipher.inputs
        cp_constraints = []
        if weight == -1:
            cp_constraints.append('solve:: int_search(p, smallest, indomain_min, complete) minimize weight;')
        else:
            cp_constraints.append(solve_satisfy)
        new_constraint = 'output['
        for element in cipher_inputs:
            new_constraint = new_constraint + f'\"{element} = \"++ show({element}) ++ \"\\n\" ++'
        for component in self._cipher.get_all_components():
            if SBOX in component.type:
                new_constraint = new_constraint + \
                    f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ ' \
                    f'show(p[{self.component_and_probability[component.id]}]/100) ++ \"\\n\" ++'
            elif WORD_OPERATION in component.type:
                new_constraint = self.get_word_operation_xor_differential_constraints(component, new_constraint, milp_modadd)
            else:
                new_constraint = new_constraint + f'\"{component.id} = \"++ ' \
                                                  f'show({component.id})++ \"\\n\" ++'
        new_constraint = new_constraint + '\"Upper weight = \" ++ show(upper_weight/100) ++ \"\\n\" ++'
        new_constraint = new_constraint + '\"Lower weight = \" ++ show(lower_weight/100) ++ \"\\n\" ++'
        new_constraint = new_constraint + '\"Middle weight = \" ++ show(middle_weight/100) ++ \"\\n\" ++'
        new_constraint = new_constraint + '\"Trail weight = \" ++ show(weight/100)  ++ \"\\n\" ++'
        new_constraint = new_constraint + '\"2^-\" ++ show(upper_bound_weight/100) ++ \" => Probability Boomerang => 2^-\" ++ show(weight/100)  ];'
        cp_constraints.append(new_constraint)

        return cp_constraints
    
    def get_word_operation_xor_differential_constraints(self, component, new_constraint, milp_modadd = False):
        if 'AND' in component.description[0] or (('MODADD' in component.description[0] or 'MODSUB' in component.description[0]) and not milp_modadd):
            new_constraint = new_constraint + f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ '
            id_without_prefix = component.id.removeprefix('upper_').removeprefix('lower_')
            if 'upper' in component.id and any(id_without_prefix in k for k in self.component_and_probability.keys()):
                id_middle = 'middle_' + component.id.removeprefix('upper_')
                if id_middle in self.component_and_probability:
                    new_constraint = new_constraint + '\"middle probability = \"++ show('
                    new_constraint = new_constraint + f'middle_p[{self.component_and_probability[id_middle][0]}]/100+'
                else:
                    new_constraint = new_constraint + '\"upper probability = \"++ show('
                    new_constraint = new_constraint + f'upper_p[{self.component_and_probability[component.id][0]}]/100+'
                new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++'
                
            elif 'lower' in component.id and any(id_without_prefix in k for k in self.component_and_probability.keys()):
                id_middle = 'middle_' + component.id.removeprefix('lower_')
                if id_middle in self.component_and_probability:
                    new_constraint = new_constraint + '\"middle probability = \"++ show('
                    new_constraint = new_constraint + f'middle_p[{self.component_and_probability[id_middle][0]}]/100+' 
                else: 
                    new_constraint = new_constraint + '\"lower probability = \"++ show('
                    new_constraint = new_constraint + f'lower_p[{self.component_and_probability[component.id][0]}]/100+'
                
                new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++'
            self.component_and_probability = {k: v for k, v in self.component_and_probability.items() if id_without_prefix not in k}

        else:
            new_constraint = new_constraint + f'\"{component.id} = \"++ ' \
                                              f'show({component.id})++ \"\\n\" ++'

        return new_constraint
    
    ##############################################################
    @staticmethod
    def bct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, branch_size):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = []
        delta_right_vars = []
        nabla_left_vars = []
        nabla_right_vars = []
        for i in range(branch_size):
            delta_left_vars.append(f'{delta_left_component_id}[{branch_size - 1 - i}]')
            delta_right_vars.append(f'{delta_right_component_id}[{branch_size - 1 - i}]')
            nabla_left_vars.append(f'{nabla_left_component_id}[{branch_size - 1 - i}]')
            nabla_right_vars.append(f'{nabla_right_component_id}[{branch_size - 1 - i}]')
        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'

        constraint = [
            f"constraint onlyLargeSwitch_BCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, 1, {branch_size}) = true;\n"
        ]
        return constraint
    
    @staticmethod
    def evaluation_ebct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, delta_left_left_component_id, nabla_left_left_component_id, branch_size, index):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = [f'{delta_left_component_id}[{i}]' for i in range(branch_size)]
        delta_right_vars = [f'{delta_right_component_id}[{ i}]' for i in range(branch_size)]
        nabla_left_vars = [f'{nabla_left_component_id}[{i}]' for i in range(branch_size)]
        nabla_right_vars = [f'{nabla_right_component_id}[{i}]' for i in range(branch_size)]
        delta_left_left_vars = [f'{delta_left_left_component_id}[{i}]' for i in range(branch_size)]
        nabla_left_left_vars = [f'{nabla_left_left_component_id}[{i}]' for i in range(branch_size)]

        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)
        delta_left_left_str = ",".join(delta_left_left_vars)
        nabla_left_left_str = ",".join(nabla_left_left_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'
        delta_left_left = f'array1d(0..{branch_size}-1, [{delta_left_left_str}])'
        nabla_left_left = f'array1d(0..{branch_size}-1, [{nabla_left_left_str}])'

        constraint = [
            f"constraint ebct_compute({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {delta_left_left}, {nabla_left_left}, {branch_size}, middle_p[{index}], upper_bound_middle_p[{index}]);\n"
        ]
        return constraint
    
    @staticmethod
    def ebct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, delta_left_left_component_id, nabla_left_left_component_id, branch_size):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = [f'{delta_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        delta_right_vars = [f'{delta_right_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_left_vars = [f'{nabla_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_right_vars = [f'{nabla_right_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        delta_left_left_vars = [f'{delta_left_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_left_left_vars = [f'{nabla_left_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]

        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)
        delta_left_left_str = ",".join(delta_left_left_vars)
        nabla_left_left_str = ",".join(nabla_left_left_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'
        delta_left_left = f'array1d(0..{branch_size}-1, [{delta_left_left_str}])'
        nabla_left_left = f'array1d(0..{branch_size}-1, [{nabla_left_left_str}])'

        ## to better understand the meaning of halfNum
        halfNum = branch_size * 2

        constraint = [
            f"constraint onlyLargeSwitch_EBCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {delta_left_left}, {nabla_left_left}, {halfNum}, {branch_size}) = true;\n"
        ]
        return constraint
    
    @staticmethod
    def evaluation_lbct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, nabla_left_left_component_id, branch_size, index):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = [f'{delta_left_component_id}[{i}]' for i in range(branch_size)]
        delta_right_vars = [f'{delta_right_component_id}[{ i}]' for i in range(branch_size)]
        nabla_left_vars = [f'{nabla_left_component_id}[{i}]' for i in range(branch_size)]
        nabla_right_vars = [f'{nabla_right_component_id}[{i}]' for i in range(branch_size)]
        nabla_left_left_vars = [f'{nabla_left_left_component_id}[{i}]' for i in range(branch_size)]

        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)
        nabla_left_left_str = ",".join(nabla_left_left_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'
        nabla_left_left = f'array1d(0..{branch_size}-1, [{nabla_left_left_str}])'

        constraint = [
            f"constraint lbct_compute({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {nabla_left_left}, {branch_size}, middle_p[{index}], upper_bound_middle_p[{index}]);\n"
        ]
        return constraint
    
    @staticmethod
    def lbct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, nabla_left_left_component_id, branch_size):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = [f'{delta_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        delta_right_vars = [f'{delta_right_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_left_vars = [f'{nabla_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_right_vars = [f'{nabla_right_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_left_left_vars = [f'{nabla_left_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]

        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)
        nabla_left_left_str = ",".join(nabla_left_left_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'
        nabla_left_left = f'array1d(0..{branch_size}-1, [{nabla_left_left_str}])'

        ## to better understand the meaning of halfNum
        halfNum = branch_size * 2

        constraint = [
            f"constraint onlyLargeSwitch_LBCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {nabla_left_left}, {halfNum}, {branch_size}) = true;\n"
        ]
        return constraint
    
    @staticmethod
    def evaluation_ubct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, delta_left_left_component_id, branch_size, index):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = [f'{delta_left_component_id}[{i}]' for i in range(branch_size)]
        delta_right_vars = [f'{delta_right_component_id}[{i}]' for i in range(branch_size)]
        nabla_left_vars = [f'{nabla_left_component_id}[{i}]' for i in range(branch_size)]
        nabla_right_vars = [f'{nabla_right_component_id}[{i}]' for i in range(branch_size)]
        delta_left_left_vars = [f'{delta_left_left_component_id}[{i}]' for i in range(branch_size)]
        
        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)
        delta_left_left_str = ",".join(delta_left_left_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'
        delta_left_left = f'array1d(0..{branch_size}-1, [{delta_left_left_str}])'

        constraint = [
            f"constraint ubct_compute({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {delta_left_left}, {branch_size}, middle_p[{index}], upper_bound_middle_p[{index}]);\n"
        ]
        return constraint
    
    @staticmethod
    def ubct_mzn_constraint_from_component_ids(delta_left_component_id, delta_right_component_id, nabla_left_component_id, nabla_right_component_id, delta_left_left_component_id, branch_size):
        # variables = []
        # branch_size = self.output_bit_size
        delta_left_vars = [f'{delta_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        delta_right_vars = [f'{delta_right_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_left_vars = [f'{nabla_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        nabla_right_vars = [f'{nabla_right_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        delta_left_left_vars = [f'{delta_left_left_component_id}[{branch_size - 1 - i}]' for i in range(branch_size)]
        
        delta_left_str = ",".join(delta_left_vars)
        delta_right_str = ",".join(delta_right_vars)
        nabla_left_str = ",".join(nabla_left_vars)
        nabla_right_str = ",".join(nabla_right_vars)
        delta_left_left_str = ",".join(delta_left_left_vars)

        delta_left = f'array1d(0..{branch_size}-1, [{delta_left_str}])'
        delta_right = f'array1d(0..{branch_size}-1, [{delta_right_str}])'
        nabla_left = f'array1d(0..{branch_size}-1, [{nabla_left_str}])'
        nabla_right = f'array1d(0..{branch_size}-1, [{nabla_right_str}])'
        delta_left_left = f'array1d(0..{branch_size}-1, [{delta_left_left_str}])'

        ## to better understand the meaning of halfNum
        halfNum = branch_size * 2

        constraint = [
            f"constraint onlyLargeSwitch_UBCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {delta_left_left}, {halfNum}, {branch_size}) = true;\n"
        ]
        return constraint
    
    def initial_constrain(self):
        for inputs in self.cipher.inputs:
            if 'upper_plaintext' in inputs:
                self._model_constraints.append(f'constraint sum({inputs})>0;')
            if 'lower_cipher_output' in inputs:
                self._model_constraints.append(f'constraint sum({inputs})>0;')
        return      
        
    def build_hadipour_boomerang_model(self, weight=-1):
        component_and_model_types = _generate_component_model_types(
            self.cipher,
            model_type="cp_xor_differential_propagation_constraints_boomerang"
        )
        
        self.initialise_model()
        self.c_upper = 0
        self.c_lower = 0
        self.sbox_mant = []
        self.input_sbox = []
        self.component_and_probability = {}
        self.table_of_solutions_length = 0
        self.branch_size = 0
        self.boomerang = True

        self.build_generic_mzn_model_from_dictionary(component_and_model_types)
        self.initial_constrain()

        variables, constraints = self.input_xor_differential_constraints()
        self._model_prefix.extend(variables)
        self._model_constraints.extend(constraints)
    
        for input in self.cipher._inputs:
            if 'plaintext' not in input and 'cipher_output' not in input:
                self._model_constraints.extend([f'constraint sum({input}) = 0;'])
        
        self._model_constraints.extend(self.final_xor_differential_constraints(weight))
        self._model_constraints = self._model_prefix + self._model_constraints
        if self.middle_part_number_of_rounds == 1:
            self._model_constraints.extend([get_bct_operations()])
        else:
            self._model_constraints.extend([get_lbct_operations()])
            self._model_constraints.extend([get_ubct_operations()])
            self._model_constraints.extend([get_evaluation_ubct_operations(self.branch_size)])
            self._model_constraints.extend([get_evaluation_lbct_operations(self.branch_size)])
            self._model_constraints.extend([get_approx_logarithm_operation_lower_bound()])
            self._model_constraints.extend([get_approx_logarithm_operation_upper_bound()])
            if self.middle_part_number_of_rounds > 2:
                self._model_constraints.extend([get_ebct_operations()])
                self._model_constraints.extend([get_evaluation_ebct_operations(self.branch_size)])

        self.write_minizinc_model_to_file(".")

        # # debug stuff
        # from mzn_boomerang_model_arx_optimized_test import speck32_64_bct_distinguisher_verifier
        # delta_up = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        # nabla_lo = [1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0]
        # number_rounds = 10
        # primi_16_delta_up = delta_up[:16]
        # ultimi_16_delta_up = delta_up[16:]
        # dec_primi_delta = sum(bit << (15 - i) for i, bit in enumerate(primi_16_delta_up))
        # dec_ultimi_delta = sum(bit << (15 - i) for i, bit in enumerate(ultimi_16_delta_up))
        # primi_16_nabla_lo = nabla_lo[:16]
        # ultimi_16_nabla_lo = nabla_lo[16:]
        # dec_primi_nabla = sum(bit << (15 - i) for i, bit in enumerate(primi_16_nabla_lo))
        # dec_ultimi_nabla = sum(bit << (15 - i) for i, bit in enumerate(ultimi_16_nabla_lo))        
        # prob = speck32_64_bct_distinguisher_verifier([dec_primi_delta,dec_ultimi_delta], [dec_primi_nabla,dec_ultimi_nabla], nr=number_rounds, n=2 ** 30 )
        # print(f'prob = {prob}')
        # if prob > 0:
        #     exponent = math.log(prob, 2)
        #     print(f'2^{exponent}')