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

from copy import deepcopy

########## as mzn_xor_differential_model.py
import math
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import update_and_or_ddt_valid_probabilities
from sage.crypto.sbox import SBox
####################


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

        #### try to imitiate MznXorDifferentialModel
        self._first_step = []
        self._first_step_find_all_solutions = []
        self._cp_xor_differential_constraints = []
        #################################

        super().__init__(unified_cipher)

    ##### I tried to copy a bit what it is happenend inside mzn_xor_differential_model ####################################
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
        
        valid_probabilities = valid_probabilities_lower | valid_probabilities_upper
        total_declatation_of_p = f'array[0..{len(just_upper_keys) + len(just_lower_keys) + len(middle_keys)}] of var {valid_probabilities}: p;'
        self._cp_xor_differential_constraints.append(total_declatation_of_p)

        count_index_for_assign_p_with_upper_lower_middle_p = 0

        #### i have to split in two, one for lower and one for upper
        cp_declarations_weight_upper = 'int: upper_weight = 0;'
        if prob_count_upper > 0:
            new_declaration_upper = f'array[0..{prob_count_upper}] of var {valid_probabilities_upper}: upper_p;'
            self._cp_xor_differential_constraints.append(new_declaration_upper)
            if self.top_part_number_of_rounds > 0:
                cp_declarations_weight_upper = 'var int: upper_weight ='
                for key in just_upper_keys:
                    cp_declarations_weight_upper += f' upper_p[{self.component_and_probability[key][0]}] +'
                    contrains_of_p_upper = f'constraint p[{count_index_for_assign_p_with_upper_lower_middle_p}] = upper_p[{self.component_and_probability[key][0]}];'
                    self._cp_xor_differential_constraints.append(contrains_of_p_upper)
                    count_index_for_assign_p_with_upper_lower_middle_p += 1
                cp_declarations_weight_upper = cp_declarations_weight_upper[:-2] + ';'
                #### it would be the weights of e0
                
        self._cp_xor_differential_constraints.append(cp_declarations_weight_upper)

        cp_declarations_weight_lower = 'int: lower_weight = 0;'
        if prob_count_lower > 0:
            new_declaration_lower = f'array[0..{prob_count_lower}] of var {valid_probabilities_lower}: lower_p;'
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
                #### it would be the len of e1
                
        self._cp_xor_differential_constraints.append(cp_declarations_weight_lower)

        
        new_declaration_middle = f'array[0..{len(middle_keys)}] of var {valid_probabilities}: middle_p;'
        self._cp_xor_differential_constraints.append(new_declaration_middle)

        self.count_middle_p = 0
        self.count_index_for_assign_p_with_upper_lower_middle_p = count_index_for_assign_p_with_upper_lower_middle_p
        #I have to sort the middle_keys in depending on the round where we are
        middle_keys = sorted(middle_keys, key=lambda x: int(x.split('_')[1]))
        
        # declaration of a vector to count the common active bits in lower and upper
        # (to write better)
        for middle_non_linear_transition_ids in middle_keys:
            round = int(middle_non_linear_transition_ids.split('_')[1])           
            middle_non_linear_transition_ids_up = 'upper_' + middle_non_linear_transition_ids
            branch_size = self.cipher.get_component_from_id(middle_non_linear_transition_ids_up).output_bit_size
            self._model_constraints.extend([f'array[0..{branch_size}] of var 0..1: common_middle_active_bits_{round};'])
        

        if self.middle_part_number_of_rounds == 1:
            #case just bct
            middle_non_linear_transition_ids = middle_keys[0]
            round = int(middle_non_linear_transition_ids.split('_')[1]) 
            deltaL, deltaR, nablaL, nablaR, _, _, branch_size = self.addSwitch(middle_non_linear_transition_ids, round)
            self._model_constraints.extend(MznHadipourBoomerangModel.bct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, branch_size))
        else:
            # print(middle_keys)
            # add ubct and lbct at the, respectively, beginning and end of the cipher
            middle_non_linear_transition_ids = middle_keys.pop(0)
            # print(middle_non_linear_transition_ids)
            # print(middle_keys)
            round = int(middle_non_linear_transition_ids.split('_')[1]) 
            deltaL, deltaR, nablaL, nablaR, deltaLL, _, branch_size = self.addSwitch(middle_non_linear_transition_ids, round)
            self._model_constraints.extend(MznHadipourBoomerangModel.ubct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, deltaLL, branch_size))

            middle_non_linear_transition_ids = middle_keys.pop()
            # print(middle_non_linear_transition_ids)
            # print(middle_keys)
            round = int(middle_non_linear_transition_ids.split('_')[1]) 
            deltaL, deltaR, nablaL, nablaR, _, nablaLL, branch_size = self.addSwitch(middle_non_linear_transition_ids, round)
            self._model_constraints.extend(MznHadipourBoomerangModel.lbct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, nablaLL, branch_size))

            if len(middle_keys) > 0:        
                for middle_non_linear_transition_ids in middle_keys:
                    # print(middle_non_linear_transition_ids)
                    round = int(middle_non_linear_transition_ids.split('_')[1]) 
                    deltaL, deltaR, nablaL, nablaR, deltaLL, nablaLL, branch_size = self.addSwitch(middle_non_linear_transition_ids, round)
                    self._model_constraints.extend(MznHadipourBoomerangModel.ebct_mzn_constraint_from_component_ids(deltaL, deltaR, nablaL, nablaR, deltaLL, nablaLL, branch_size))

        cp_declarations_weight_middle = 'var int: middle_weight = sum(middle_p);'
        self._cp_xor_differential_constraints.append(cp_declarations_weight_middle)

        new_declaration = 'var int: weight = (2 * upper_weight) + (2 * lower_weight) + middle_weight;'
        self._cp_xor_differential_constraints.append(new_declaration)

        variables = []
        return variables, self._cp_xor_differential_constraints
    
    def addSwitch(self, middle_non_linear_transition_ids, round):
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

        # if both the element are active then we propagate with a certain probability 
        # I set the diffution of the middle probability bit a bit, i.e we count the active bit if both
        # the lower and upper bit are active then we count the probability of the middle
        for i in range(branch_size):
            middle_constrain_bit = f'constraint if ({deltaLL}[{i}] > 0) /\\ ({nablaLL}[{i}] > 0) then common_middle_active_bits_{round}[{i}]>0 endif;'
            self._cp_xor_differential_constraints.append(middle_constrain_bit)
        middle_constrain = f'constraint middle_p[{self.count_middle_p}] = ({branch_size}-sum(common_middle_active_bits_{round}))*100;'
        self._cp_xor_differential_constraints.append(middle_constrain)

        # deltaLL_element = '('
        # nablaLL_element = '('
        # for i in range(branch_size):
        #     deltaLL_element = deltaLL_element + f'({deltaLL}[{i}] > 0) \\/ '
        #     nablaLL_element = nablaLL_element + f'({nablaLL}[{i}] > 0) \\/ '
        # deltaLL_element = deltaLL_element[:-3] + ")"
        # nablaLL_element = nablaLL_element[:-3] + ")"

        # middle_constrain = f'constraint if {deltaLL_element} /\\ {nablaLL_element} then middle_p[{self.count_middle_p}]>0 endif;'
        # self._cp_xor_differential_constraints.append(middle_constrain)

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
        new_constraint = new_constraint + '\"Trail weight = \" ++ show(weight/100)];'
        cp_constraints.append(new_constraint)

        return cp_constraints
    
    def get_word_operation_xor_differential_constraints(self, component, new_constraint, milp_modadd = False):
        if 'AND' in component.description[0] or (('MODADD' in component.description[0] or 'MODSUB' in component.description[0]) and not milp_modadd):
            new_constraint = new_constraint + f'\"{component.id} = \"++ show({component.id})++ \"\\n\" ++ '
            if 'upper' in component.id:
                new_constraint = new_constraint + '\"upper probability = \"++ show('
                for i in range(len(self.component_and_probability[component.id])):
                    new_constraint = new_constraint + f'upper_p[{self.component_and_probability[component.id][i]}]/100+'
                id_middle = 'middle_' + component.id.removeprefix('upper_')
                if id_middle in self.component_and_probability:
                    new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++ \"middle probability = \"++ show('
                    for i in range(len(self.component_and_probability[component.id])):
                        new_constraint = new_constraint + f'middle_p[{self.component_and_probability[id_middle][i]}]/100+'
            elif 'lower' in component.id:
                new_constraint = new_constraint + '\"lower probability = \"++ show('
                for i in range(len(self.component_and_probability[component.id])):
                    new_constraint = new_constraint + f'lower_p[{self.component_and_probability[component.id][i]}]/100+'
                    id_middle = 'middle_' + component.id.removeprefix('lower_')
                if id_middle in self.component_and_probability:
                    new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++ \"middle probability = \"++ show('
                    for i in range(len(self.component_and_probability[component.id])):
                        new_constraint = new_constraint + f'middle_p[{self.component_and_probability[id_middle][i]}]/100+' 
            new_constraint = new_constraint[:-1] + ') ++ \"\\n\" ++'

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

        constraint = [
            f"constraint onlyLargeSwitch_EBCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {delta_left_left}, {nabla_left_left}, 1, {branch_size}) = true;\n"
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

        constraint = [
            f"constraint onlyLargeSwitch_LBCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {nabla_left_left}, 1, {branch_size}) = true;\n"
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

        constraint = [
            f"constraint onlyLargeSwitch_UBCT_enum({delta_left}, {delta_right}, "
            f"{nabla_left}, {nabla_right}, {delta_left_left}, 1, {branch_size}) = true;\n"
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
        #### in self.cipher we have the unified cipher

        #### middle components:
        # em_components = []
        # nr_0 = self.top_part_number_of_rounds
        # nr_m = self.middle_part_number_of_rounds
        # for round_number in range(nr_0, nr_0 + nr_m):
        #     em_components.extend(self.cipher.get_components_in_round(round_number))
        # em_components_ids_non_linear_layer = []
        # for em_component in em_components:
        #     if 'modadd' in em_component.id:
        #         em_components_ids_non_linear_layer.append(em_component.id)
       
        # by default we are defining every component to have a pure differential modeling
        component_and_model_types = _generate_component_model_types(
            self.cipher,
            model_type="cp_xor_differential_propagation_constraints_boomerang"
        )

        self.cipher.print_as_python_dictionary()
        
        self.initialise_model()
        self.c = 0
        self.c_upper = 0
        self.c_lower = 0
        # self.upper_probabilities_and_index = {}
        # self.lower_probabilities_and_index = {}
        self.sbox_mant = []
        self.input_sbox = []
        self.component_and_probability = {}
        self.table_of_solutions_length = 0
        self.boomerang = True

        self.build_generic_mzn_model_from_dictionary(component_and_model_types)
        self.initial_constrain()

        # print("self.c ", self.c)
        # print("self.c_upper ", self.c_upper)
        # print("self.c_lower ", self.c_lower)
        # assert self.c_upper == self.c_lower
        # print("self.upper_probabilities ", self.upper_probabilities_and_index)
        # print("self.lower_probabilities ", self.lower_probabilities_and_index)
        # print("self.sbox_mant ", self.sbox_mant)
        # print("self.input_sbox ", self.input_sbox)
        # print("self.component_and_probability ", self.component_and_probability)

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
            if self.middle_part_number_of_rounds > 2:
                self._model_constraints.extend([get_ebct_operations()])


        # add constrain to have same output of sat aided
        # speck 32-64 1-2-1 rounds
        ## replicated solution in SAT CODE
        # ## L0_up,R0_up = [2800, 0010]
        # input_plaintext_left = "0010100000000000"
        # input_plaintext_right = "0000000000010000"
        # ## L4_lo,R4_lo = [8102, 8108]
        # outpu_cihertext_left = "1000000100000010" 
        # outpu_cihertext_right = "1000000100001000"

        ## unstatisfaiable
        ## L1_up,R1_up = [8000, 8000]
        input_plaintext_left = "1000000000000000"
        input_plaintext_right = "1000000000000000"
        ## L3_lo,R3_lo = [0000, 8000]
        outpu_cihertext_left = "0000000000000000" 
        outpu_cihertext_right = "1000000000000000"

        input_bits_left = list(input_plaintext_left)
        input_bits_right = list(input_plaintext_right)
        output_bits_left = list(outpu_cihertext_left)
        output_bits_right = list(outpu_cihertext_right)
        for inputs in self.cipher.inputs:
            if 'upper_plain' in inputs:
                name_input_plain = inputs
            if 'lower_cipher' in inputs:
                name_output_cipher = inputs
        for i in range(16):
            self._model_constraints.extend([f"constraint {name_input_plain}[{i}] = {input_bits_left[i]};"])
        for i in range(16):
            self._model_constraints.extend([f"constraint {name_input_plain}[{16+i}] = {input_bits_right[i]};"])
        for i in range(16):
            self._model_constraints.extend([f"constraint {name_output_cipher}[{i}] = {output_bits_left[i]};"])
        for i in range(16):
            self._model_constraints.extend([f"constraint {name_output_cipher}[{16+i}] = {output_bits_right[i]};"])

        # middle_keys = [key for key in self.component_and_probability if 'middle' in key]
        # middle_keys = sorted(middle_keys, key=lambda x: int(x.split('_')[2]))

        # # that one is a solution i found in sat code
        # input_ubct_up_left = list("1100000000000000")
        # input_ubct_up_right = list("0000000000100000")
        # input_ubct_lo_left = list("1100110001111100")
        # input_ubct_lo_right = list("1110110011111111")
        # output_ubct = list("0100000001100000")
        # input_lbct_up_left = list("1100000010000000")
        # input_lbct_up_right = list("0100000011100000")
        # input_lbct_lo_left = list("0111111000001111")
        # input_lbct_lo_right = list("0111111110000011")
        # output_lbct = list("1111100110011000")

        ## first middle key for the ubct constrain
        # key = middle_keys.pop(0)
        # upper_key = key.replace("middle", "upper")
        # lower_key = key.replace("middle", "lower")
        # for i in range(16):
        #     self._model_constraints.extend([f"constraint pre_{upper_key}_0[{i}] = {input_ubct_up_left[i]};"]) 
        #     self._model_constraints.extend([f"constraint pre_{upper_key}_1[{i}] = {input_ubct_up_right[i]};"]) 
        #     self._model_constraints.extend([f"constraint pre_{lower_key}_0[{i}] = {input_ubct_lo_left[i]};"]) 
        #     self._model_constraints.extend([f"constraint pre_{lower_key}_1[{i}] = {input_ubct_lo_right[i]};"])
        #     # self._model_constraints.extend([f"constraint {upper_key}[{i}] = {output_ubct[i]};"])

        # # # block dLL and nLL found in claasp
        # output_ubct = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # output_lbct = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # extra_constrain = "constraint not ("
        # for i in range(16):
        #     extra_constrain = extra_constrain + f"({upper_key}[{i}] = {output_ubct[i]}) /\\ "
        # extra_constrain = extra_constrain[:-3] + ");"
        # # print(extra_constrain)
        # self._model_constraints.extend([extra_constrain])

        # key = middle_keys.pop()
        # extra_constrain = "constraint not ("
        # for i in range(16):
        #     extra_constrain = extra_constrain + f"({lower_key}[{i}] = {output_lbct[i]}) /\\ "
        # extra_constrain = extra_constrain[:-3] + ");"
        # # print(extra_constrain)
        # self._model_constraints.extend([extra_constrain])

        # # block dL and nL (in this case they are the same) solution found in claasp
        # dL_ubct = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # extra_constrain = "constraint not("
        # for i in range(16):
        #     extra_constrain = extra_constrain + f"(pre_{upper_key}_0[{i}] = {dL_ubct[i]}) /\\ "
        # extra_constrain = extra_constrain[:-3] + ");"
        # # print(extra_constrain)
        # self._model_constraints.extend([extra_constrain])

        # key = middle_keys.pop()
        # extra_constrain = "constraint not("
        # for i in range(16):
        #     extra_constrain = extra_constrain + f"(pre_{lower_key}_0[{i}] = {dL_ubct[i]}) /\\ "
        # extra_constrain = extra_constrain[:-3] + ");"
        # # print(extra_constrain)
        # self._model_constraints.extend([extra_constrain])
        

        # key = middle_keys.pop()
        # upper_key = key.replace("middle", "upper")
        # lower_key = key.replace("middle", "lower")
        # for i in range(16):
        #     self._model_constraints.extend([f"constraint pre_{upper_key}_0[{i}] = {input_lbct_up_left[i]};"]) 
        #     self._model_constraints.extend([f"constraint pre_{upper_key}_1[{i}] = {input_lbct_up_right[i]};"]) 
        #     self._model_constraints.extend([f"constraint pre_{lower_key}_0[{i}] = {input_lbct_lo_left[i]};"]) 
        #     self._model_constraints.extend([f"constraint pre_{lower_key}_1[{i}] = {input_lbct_lo_right[i]};"])
        #     # self._model_constraints.extend([f"constraint {lower_key}[{i}] = {output_lbct[i]};"])
        

        # for constrains in self._model_constraints:
        #     if 'carry' in constrains:
        #         print(constrains)

        # # middle_variable_non_linar = []
        # for components in em_components:
        #     # app = []
        #     # print(components)
        #     if components.type == SBOX:
        #         print(components.description)
        #     elif components.type == WORD_OPERATION and components.description[0] == 'MODADD':
        #             print(components.description)
        #             # app.append(components.description[0])
        #             # print(components.id)
        #             # em_non_linear_components.extend(components)
        #     # print(app)
        #     # if len(app) == 2:
        #     #     self._variables_list.append('array[0..15] of var 0..1: middle_modadd_2_7_0;')
        # # print(middle_variable_non_linar)

        # for variable in self._variables_list:
        #     if variable.startswith('array[0..15] of var 0..1: pre_upper_modadd_0_1_'):
        #         print(variable)
        # # print("variables = ", self._variables_list)
        
        # import ipdb;
        # ipdb.set_trace()

        ## TODO::Add condition to sum of plaintext and ciphertext to be greater than 0 otherwise it will find with all 0s
        ## TODO::Print as well of the upper and lower weights

        # TODO:: Add Hadipour constraints - Constrain for the middle part
        # TODO:: Define the objective

        from mzn_boomerang_model_arx_optimized_test import speck32_64_bct_distinguisher_verifier
        # plaintext = [24, 2**11]
        # # [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0,
        # #  0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # #  [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        # #   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        # ciphertext = [2**15, 2**15+2**10 + 10]
        # # [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        # #  1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]
        # #  [1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 
        # #   1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0]
        # nr = 9
        # print(speck32_64_bct_distinguisher_verifier(plaintext, ciphertext, nr, n=2 ** 25 ))

        # delta_befor_mod_add_up = [2**8, 2**15+2**10+10]
        # # # 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        # # # 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0
        # nabla_before_mod_add_lo = [2**6, 2**4]
        # # # 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
        # # # 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0
        # nr = 1
        # # upper_rot_4_6
        # # upper_xor_3_10
        # # lower_xor_4_8
        # # lower_rot_4_9
        # print(speck32_64_bct_distinguisher_verifier(delta_befor_mod_add_up, nabla_before_mod_add_lo, nr, n=2 ** 20))
        # inpud_delta_upp_mod_add = [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0]]
        # input_nabla_low_mod_sub = [[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0]]

        # delta_up = [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1]
        # nabla_lo = [1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0]
        # delta_up = [0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        # nabla_lo = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]
        # delta_up = [0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0]
        # nabla_lo = [0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0]
        # number_rounds = self.top_part_number_of_rounds + self.bottom_part_number_of_rounds + self.middle_part_number_of_rounds


        # # round 8 3-2-3 ubct and lbct
        # delta_up = [1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        # nabla_lo = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0]
        # number_rounds = 8
        # # prob = 5.960464477539063e-08 = 2^-24.0
        # # n = 25 (to put in verifier)
        # # output minizinc -26.00

        # # round 9 3-3-3 ubct and lbct and 1 ebct
        # delta_up = [1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0]
        # nabla_lo = [1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0]
        # number_rounds = 9
        # # prob = 0.0
        # # n = 25 (to put in verifier)
        # # output minizinc -47.00

        # round 10 3-4-3 ubct and lbct and 2 ebct -> Unsatisfaiable
        # number_rounds = 10
        # prob = 0.0
        # n = 25 (to put in verifier)
        # output minizinc -47.00

        # # round 5 1-3-1
        # number_rounds = 5
        # delta_up = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        # nabla_lo = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0]
        # # n = 25
        # # prob =
        # # output Minizinc -11.00

        ##  EXPERIMENT 1-2-1
        # PROBABILITY SAT 2^{-17.2308}

        # # input modular addition round 1 in lower side: ['lower_xor_1_8', 'lower_rot_1_9'],, output [lower_modadd_1_7]
        # # input modular addition round 1 in upper side: ['upper_rot_1_6', 'upper_xor_0_4'], output [upper_modadd_1_7]
        # # input modular addition round 2 in lower side: ['lower_xor_2_8', 'lower_rot_2_9'],, output [lower_modadd_2_7]
        # # input modular addition round 2 in upper side: ['upper_rot_2_6', 'upper_xor_1_10'], output [upper_modadd_2_7]
        # # check if the input of ubct with fixed input found in claasp could be a solution for SAT AIDED
        # # input ubct solution found:
        # # dL = upper_rot_1_6 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # dR = upper_xor_0_4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 0
        # # nL = lower_xor_1_8 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 0
        # # nR = lower_rot_1_9 = [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^13 = 8192
        # # dLL = upper_modadd_1_7 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # input lbct solution found:
        # # dL = upper_rot_2_6 = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0] = 2^8 = 256
        # # dR = upper_xor_1_10 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # nL = lower_xor_2_8 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # nR = lower_rot_2_9 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # nLL = lower_modadd_2_7 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 0

        #INPUT UBCT AND LBCT OF ONE SOLUTION OF SAT AIDED
        # ubct switcht
        # 0b1100000000000000 | 0b0000000000100000 | 0b1100110001111100 | 0b1110110011111111 | 0b0100000001100000 |
        # lbct
        # 0b1100000010000000 | 0b0100000011100000 | 0b0111111000001111 | 0b0111111110000011 | 0b1111100110011000 |
        # ### experiments claasp 1-2-1:
        # delta_up = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # nabla_lo = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
        # number_rounds = 4
        # # n = 20
        # # prob = 2^-0.1929
        # # output Minizinc -2.00


        # ### experiment claasp 1-2-1, upper_plain e lower_cipher fixed as sat-aided:
        # delta_up = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        # nabla_lo = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0]
        # number_rounds = 4
        # # n = 20
        # # prob = 2^-7.34
        # # output Minizinc -8.00

        # delta_up = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # nabla_lo = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        # number_rounds = 2


        # ### experiment claasp 1-2-1, upper_plain e lower_cipher fixed and inputs of ubct and lbct as a solution of sat-aided:
        # ## UNSITASAIALBLE

        # ### experiment claasp 1-2-1, upper_plain e lower_cipher fixed and inputs of ubct and lbct excpet the output of the moduluar addition as a solution of sat-aided:
        # ## UNSITASAIALBLE

        # # input modular addition round 1 in lower side: ['lower_xor_1_8', 'lower_rot_1_9'],, output [lower_modadd_1_7]
        # # input modular addition round 1 in upper side: ['upper_rot_1_6', 'upper_xor_0_4'], output [upper_modadd_1_7]
        # # input modular addition round 2 in lower side: ['lower_xor_2_8', 'lower_rot_2_9'],, output [lower_modadd_2_7]
        # # input modular addition round 2 in upper side: ['upper_rot_2_6', 'upper_xor_1_10'], output [upper_modadd_2_7]
        # # upper_rot_1_6 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # upper_xor_0_4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 0
        # # lower_xor_1_8 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 0
        # # lower_xor_1_9 = [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^13 = 8192
        # # upper_rot_2_6 = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0] = 2^8 = 256
        # # upper_xor_1_10 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 =32768
        # # lower_xor_2_8 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768
        # # lower_xor_2_9 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] = 2^15 = 32768


        # prob = speck32_64_bct_distinguisher_verifier(split_and_convert(delta_up), split_and_convert(nabla_lo), nr=number_rounds, n=2 ** 22 )
        # print(f'prob = {prob}')
        # if prob > 0:
        #     exponent = math.log(prob, 2)
        #     print(f'2^{exponent}')

        self.write_minizinc_model_to_file(".")

def split_and_convert(bin_list):
        if len(bin_list) != 32:
            raise ValueError("La lista deve contenere esattamente 32 elementi.")

        primi_16 = bin_list[:16]
        ultimi_16 = bin_list[16:]

        dec_primi = sum(bit << (15 - i) for i, bit in enumerate(primi_16))
        dec_ultimi = sum(bit << (15 - i) for i, bit in enumerate(ultimi_16))

        return [dec_primi, dec_ultimi]