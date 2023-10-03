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

import time
from claasp.cipher_modules.models.milp.utils.config import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_model import verbose_print
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import \
    update_dictionary_that_contains_wordwise_truncated_input_inequalities, \
    output_dictionary_that_contains_wordwise_truncated_input_inequalities
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)
from claasp.cipher_modules.models.milp.utils import utils as milp_utils


class MilpWordwiseImpossibleXorDifferentialModel(MilpWordwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
        self._forward_cipher = None
        self._backward_cipher = None

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Model 1 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294
        using the MILP technique from https://github.com/Deterministic-TD-MDLA/auxiliary_material/blob/master/Supplementary-Material.pdf

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = milp.input_wordwise_deterministic_truncated_xor_differential_constraints()
            sage: variables
             ('x[xor_0_36_11]', x_1571),
             ('x[xor_0_36_12]', x_1572),
             ...
             ('x[cipher_output_1_32_126]', x_3078),
             ('x[cipher_output_1_32_127]', x_3079)]
            sage: constraints
            [1 <= 1 + x_0 - x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9,
             1 <= 1 + x_1 - x_9,
             ...
             x_2918 == 2*x_3060 + x_3061,
             x_2919 == 2*x_3070 + x_3071]


        """

        x = self._binary_variable
        x_class = self._trunc_wordvar

        variables = []
        constraints = []

        update_dictionary_that_contains_wordwise_truncated_input_inequalities(self._word_size)
        dict_inequalities = output_dictionary_that_contains_wordwise_truncated_input_inequalities()
        inequalities = dict_inequalities[self._word_size]

        for component in self._forward_cipher.get_all_components() + self._backward_cipher.get_all_components():
            input_full_tuples, output_full_tuples = component._get_wordwise_input_output_full_tuples(self)
            all_vars = [_ for j in input_full_tuples + output_full_tuples for _ in j]

            input_class_ids, output_class_ids = component._get_wordwise_input_output_linked_class(self)
            all_int_vars = input_class_ids + output_class_ids

            for word_tuple in input_full_tuples + output_full_tuples:
                # link class tuple (c0, c1) to the possible bit values of each component word
                word_vars = [x[_] for _ in word_tuple]
                minimized_constraints = espresso_pos_to_constraints(inequalities, word_vars)
                constraints.extend(minimized_constraints)

            variables.extend([(f"x_class[{var}]", x_class[var]) for var in all_int_vars] + \
                            [(f"x[{var}]", x[var]) for var in all_vars])

            # link class tuple (c0, c1) to the integer value of the class (0, 1, 2, 3)
            input_tuples, output_tuples = component._get_wordwise_input_output_linked_class_tuples(self)
            variables_tuples = [tuple(x[i] for i in list(j)) for j in input_tuples + output_tuples]

            for index, var in enumerate(all_int_vars):
                constraints.append(
                    x_class[var] == sum([2 ** i * var_bit for i, var_bit in enumerate(variables_tuples[index][::-1])]))

        return variables, constraints

    def build_wordwise_impossible_xor_differential_trail_model(self, fixed_bits=[], fixed_words=[]):
        """
        Build the model for the search of wordwise impossible XOR differential trails.

        INPUTS:

        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._forward_cipher = aes.get_partial_cipher(0, 1, keep_key_schedule=True)
            sage: milp._backward_cipher = aes.cipher_partial_inverse(1, 1, suffix="_backward", keep_key_schedule=False)
            sage: milp.build_wordwise_impossible_xor_differential_trail_model()
            ...
        """
        self._variables_list = []
        variables, constraints = self.input_wordwise_deterministic_truncated_xor_differential_constraints()

        constraints += self.fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(fixed_bits,
            fixed_words)
        self._model_constraints = constraints

        for component in self._forward_cipher.get_all_components() + self._backward_cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                               WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.milp_wordwise_deterministic_truncated_xor_differential_constraints(
                    self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def add_constraints_to_build_in_sage_milp_class(self, middle_round, fixed_bits=[], fixed_words=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail(1, get_single_key_scenario_format_for_fixed_values(aes))

        """
        verbose_print("Building model in progress ...")

        mip = self._model
        x = self._binary_variable
        x_class = self._trunc_wordvar
        p = self._integer_variable

        assert middle_round < self._cipher.number_of_rounds

        self._forward_cipher = self._cipher.get_partial_cipher(0, middle_round-1, keep_key_schedule=True)
        self._backward_cipher = self._cipher.cipher_partial_inverse(middle_round, self._cipher.number_of_rounds - 1, suffix="_backward", keep_key_schedule=False)

        self.build_wordwise_impossible_xor_differential_trail_model(fixed_bits, fixed_words)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # finding incompatibility
        constraints = []
        forward_output = [c for c in self._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        output_size = forward_output.output_bit_size // self.word_size

        _, output_ids = forward_output._get_wordwise_input_output_linked_class(self)

        forward_vars = [x_class[id] for id in output_ids]
        backward_vars = [x_class["_".join(id.split("_")[:-3] + ["backward"] + id.split("_")[-3:])] for id in output_ids]

        inconsistent_vars = [x[f"{forward_output.id}_inconsistent_{_}"] for _ in range(output_size)]

        constraints.extend([sum(inconsistent_vars) == 1])
        for inconsistent_index in range(output_size):
            incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] <= 2]
            constraints.extend(milp_utils.milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint, self._model.get_max(x_class) * 2))

        cipher_output = [c for c in self._cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
        _, cipher_output_ids = cipher_output._get_wordwise_input_output_linked_class(self)
        constraints.extend([x_class[id] <= 1 for id in cipher_output_ids] + [sum([x_class[id] for id in cipher_output_ids]) >= 1])

        for constraint in constraints:
            mip.add_constraint(constraint)

        # unknown patterns are tuples of the form (1,x) (i.e pattern = 2 or 3)
        _, forward_output_id_tuple = forward_output._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(
        p["number_of_unknown_patterns"] == sum(x[output_msb] for output_msb in [id[0] for id in forward_output_id_tuple]))

    def find_one_wordwise_impossible_xor_differential_trail(self,  middle_round, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one wordwise impossible XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``middle_round`` -- **integer**; the round number for which the incompatibility occurs
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_model import MilpWordwiseImpossibleXorDifferentialModel
            sage: milp = MilpWordwiseImpossibleXorDifferentialModel(aes)
            sage: trail = milp.find_one_wordwise_impossible_xor_differential_trail(1, get_single_key_scenario_format_for_fixed_values(aes))

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(middle_round, fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve("wordwise_impossible_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution