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
from claasp.cipher_modules.models.milp.milp_model import MilpModel, verbose_print
from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import (
    update_dictionary_that_contains_wordwise_truncated_input_inequalities,
    output_dictionary_that_contains_wordwise_truncated_input_inequalities,
    delete_dictionary_that_contains_wordwise_truncated_input_inequalities
)


class MilpDeterministicTruncatedXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
        self._trunc_binvar = None
        self._trunc_wordvar = None
        self._word_size = 1
        if self._cipher.is_spn():
            for component in self._cipher.get_all_components():
                if SBOX in component.type:
                    self._word_size = int(component.output_bit_size)
                    break

    def init_model_in_sage_milp_class(self, solver_name=SOLVER_DEFAULT):
        """
        Initialize a MILP instance from the build-in sage class.

        INPUT:

        - ``solver_name`` -- **string**; the solver to call

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._model
            Mixed Integer Program (no objective, 0 variables, 0 constraints)
        """

        super().init_model_in_sage_milp_class(solver_name=SOLVER_DEFAULT)
        self._trunc_binvar = self._model.new_variable(integer=True, nonnegative=True)
        self._model.set_max(self._trunc_binvar, 2)
        self._trunc_wordvar = self._model.new_variable(integer=True, nonnegative=True)
        self._model.set_max(self._trunc_wordvar, 3)

    def add_constraints_to_build_in_sage_milp_class(self, fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()

        """
        verbose_print("Building model in progress ...")

        mip = self._model
        x = self._binary_variable
        p = self._integer_variable


        components = self._cipher.get_all_components()
        last_component = components[-1]


        if self._word_size == 1:
            self.build_deterministic_truncated_xor_differential_trail_model(fixed_variables)
            for index, constraint in enumerate(self._model_constraints):
                mip.add_constraint(constraint)

            # objective is the number of unknown patterns i.e. tuples of the form (1, x)

            input_id_tuples, output_id_tuples = last_component._get_input_output_variables_tuples()
            input_ids, output_ids = last_component._get_input_output_variables()
            linking_constraints = self.link_binary_tuples_to_integer_variables(input_id_tuples + output_id_tuples,
                                                                                input_ids + output_ids)
            for constraint in linking_constraints:
                mip.add_constraint(constraint)
            mip.add_constraint(p["probability"] == sum(x[output_msb] for output_msb in [id[0] for id in output_id_tuples]))

        else:
            self.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_variables)
            for index, constraint in enumerate(self._model_constraints):
                mip.add_constraint(constraint)

            # objective is the number of unknown patterns i.e. tuples of the form (1, x)
            input_ids, output_ids = last_component._get_wordwise_input_output_linked_class_tuples(self)
            mip.add_constraint(p["probability"] == sum(x[output_msb] for output_msb in [id[0] for id in output_ids]))

    def build_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[]):
        """
        Build the model for the search of bitwise deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_deterministic_truncated_xor_differential_constraints(fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                               WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                if operation in ['XOR','MODADD']:
                    variables, constraints = component.milp_deterministic_truncated_xor_differential_binary_constraints(self)
                elif component.type == SBOX:
                    variables, constraints = component.milp_undisturbed_bits_deterministic_truncated_xor_differential_constraints(self)
                else:
                    variables, constraints = component.milp_deterministic_truncated_xor_differential_constraints(self)

            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def build_wordwise_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[]):
        """
        Build the model for the search of wordwise deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: M = MilpDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_wordwise_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        self._variables_list = []

        variables, constraints = self.input_wordwise_deterministic_truncated_xor_differential_constraints()

        if fixed_variables.count(2) > 0 or fixed_variables.count(3) > 0:
            constraints+=self.fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(fixed_variables)
        else:
            constraints+=self.fix_variables_value_constraints(fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                               WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.milp_wordwise_deterministic_truncated_xor_differential_constraints(self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def fix_variables_value_deterministic_truncated_xor_differential_constraints(self, fixed_variables=[]):
        """
        Returns a list of constraints that fix the input variables to a
        specific value.

        INPUTS:

        - ``fixed_variables`` -- *list of dict*, the variables to be fixed in
          standard format

          .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(simon)
            sage: milp.init_model_in_sage_milp_class()
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'cipher_output_1_8',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: constraints = milp.fix_variables_value_deterministic_truncated_xor_differential_constraints(fixed_variables)
            sage: constraints
            [x_0 == 1,
             x_1 == 0,
             x_2 == 1,
             x_3 == 1,
             x_6 <= 6 - 3*x_4 - 3*x_5,
            ...
            -2 + 3*x_13 - 3*x_14 <= x_15,
            x_4 + x_7 + x_10 + x_13 == 1]


        """
        x_class = self._trunc_binvar

        constraints = []
        for fixed_variable in fixed_variables:
            component_id = fixed_variable["component_id"]
            if fixed_variable["constraint_type"] == "equal":
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    constraints.append(
                        x_class[component_id + '_' + str(bit_position)] == fixed_variable["bit_values"][index])
            else:
                if sum(fixed_variable["bit_values"]) == 0:
                    constraints.append(sum(x_class[component_id + '_' + str(i)]
                                           for i in fixed_variable["bit_positions"]) >= 1)
                else:
                    M = self._model.get_max(x_class) + 1
                    d = self._binary_variable
                    one_among_n = 0

                    for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                        # eq = 1 iff bit_position == diff_index
                        eq = d[component_id + "_" + str(bit_position) + "_is_diff_index"]
                        one_among_n += eq

                        # enforce that at list the component value is different at position diff_index
                        # x[diff_index] < fixed_variable[diff_index] or fixed_variable[diff_index] < x[diff_index]
                        dummy= d[component_id + "_" + str(bit_position) + "_diff_fixed_values"]
                        a = x_class[component_id + '_' + str(bit_position)]
                        b = fixed_variable["bit_values"][index]
                        constraints.extend([a <= b - 1 + M * (2 - dummy - eq),
                                       a >= b + 1 - M * (dummy + 1 - eq)])

                    constraints.append(one_among_n == 1)

        return constraints

    def fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(self, fixed_variables=[]):
        """
        Returns a list of constraints that fix the input variables to a
        specific value.

        INPUTS:

        - ``fixed_variables`` -- *list of dict*, the variables to be fixed in
          standard format

          .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'intermediate_output_0_35',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 1, 1, 0]
            ....: }]
            sage: constraints = milp.fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(fixed_variables)
            sage: constraints
            [x_0 == 1,
             x_1 == 0,
             ...
             -3 + 4*x_13 - 4*x_14 <= x_15,
             x_4 + x_7 + x_10 + x_13 == 1]


        """
        x_class = self._trunc_wordvar

        constraints = []
        for fixed_variable in fixed_variables:
            component_id = fixed_variable["component_id"]
            if fixed_variable["constraint_type"] == "equal":
                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    constraints.append(
                        x_class[component_id + '_' + str(bit_position)] == fixed_variable["bit_values"][index])
            else:
                if sum(fixed_variable["bit_values"]) == 0:
                    constraints.append(sum(x_class[component_id + '_' + str(i)]
                                           for i in fixed_variable["bit_positions"]) >= 1)
                else:
                    M = self._model.get_max(x_class) + 1
                    d = self._binary_variable
                    one_among_n = 0

                    for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                        # eq = 1 iff bit_position == diff_index
                        eq = d[component_id + "_" + str(bit_position) + "_is_diff_index"]
                        one_among_n += eq

                        # enforce that at list the component value is different at position diff_index
                        # x[diff_index] < fixed_variable[diff_index] or fixed_variable[diff_index] < x[diff_index]
                        dummy = d[component_id + "_" + str(bit_position) + "_diff_fixed_values"]
                        a = x_class[component_id + '_' + str(bit_position)]
                        b = fixed_variable["bit_values"][index]
                        constraints.extend([a <= b - 1 + M * (2 - dummy - eq),
                                            a >= b + 1 - M * (dummy + 1 - eq)])

                    constraints.append(one_among_n == 1)

        return constraints

    def link_binary_tuples_to_integer_variables(self, id_tuples, ids):
        """
        Returns constraints linking the tuple of binary variables to the associated integer variable representing the
        truncated pattern of a bit, for the bitwise deterministic truncated xor differential model
            - (0, 0) means that the pattern is 0, i.e. the bit value equals 0
            - (0, 1) means that the pattern is 1, i.e. the bit value equals 1
            - (1, 0) means that the pattern is 2, i.e. the bit value is unknown

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``id_tuples`` -- **list**; the ids list of the tuple of binary variables to be linked
        - ``ids`` -- **list**; the ids list of the integer variables to be linked

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: fancy = FancyBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(fancy)
            sage: milp.init_model_in_sage_milp_class()
            sage: component = fancy.component_from(0, 6)
            sage: input_ids, output_ids = component._get_input_output_variables()
            sage: _, input_id_tuples, output_id_tuples = component._get_input_output_variables_tuples(milp)
            sage: constraints = milp.link_binary_tuples_to_integer_variables(input_id_tuples + output_id_tuples, input_ids + output_ids)
            sage: constraints
            [x_96 == 2*x_0 + x_1,
             x_97 == 2*x_2 + x_3,
            ...
             x_142 == 2*x_92 + x_93,
             x_143 == 2*x_94 + x_95]


        """


        x = self.binary_variable
        x_class = self.trunc_binvar

        constraints = []
        variables_tuples = [tuple(x[i] for i in j) for j in id_tuples]

        variables = [x_class[i] for i in ids]
        for index, var in enumerate(variables):
            constraints.append(
                var == sum([2 ** i * var_bit for i, var_bit in enumerate(variables_tuples[index][::-1])]))

        return constraints

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Model 1 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294
        using the milp technique from https://github.com/Deterministic-TD-MDLA/auxiliary_material/blob/master/Supplementary-Material.pdf

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = milp.input_wordwise_deterministic_truncated_xor_differential_constraints_alt()
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
            sage: len(constraints)
            1783


        """

        x = self._binary_variable
        x_class = self._trunc_wordvar

        variables = []
        constraints = []

        update_dictionary_that_contains_wordwise_truncated_input_inequalities(self._word_size)
        dict_inequalities = output_dictionary_that_contains_wordwise_truncated_input_inequalities()
        inequalities = dict_inequalities[self._word_size]

        for component in self._cipher.get_all_components():
            input_full_tuples, output_full_tuples = component._get_wordwise_input_output_full_tuples(self)
            all_vars = [_ for j in input_full_tuples + output_full_tuples for _ in j]

            input_class_ids, output_class_ids = component._get_wordwise_input_output_linked_class(self)
            all_int_vars = input_class_ids + output_class_ids

            for word_tuple in input_full_tuples + output_full_tuples:
                # link class tuple (c0, c1) to the possible bit values of each component word
                for ineq in inequalities:
                    constraint = 0
                    for j, char in enumerate(ineq):
                        if char == "-":
                            continue
                        elif char == "1":
                            constraint += 1 - x[word_tuple[j]]
                        elif char == "0":
                            constraint += x[word_tuple[j]]
                    constraints.append(constraint >= 1)

            variables.extend([(f"x_class[{var}]", x_class[var]) for var in all_int_vars] + \
                            [(f"x[{var}]", x[var]) for var in all_vars])

            # link class tuple (c0, c1) to the integer value of the class (0, 1, 2, 3)
            input_tuples, output_tuples = component._get_wordwise_input_output_linked_class_tuples(self)
            variables_tuples = [tuple(x[i] for i in list(j)) for j in input_tuples + output_tuples]

            for index, var in enumerate(all_int_vars):
                constraints.append(
                    x_class[var] == sum([2 ** i * var_bit for i, var_bit in enumerate(variables_tuples[index][::-1])]))

        return variables, constraints

    def find_one_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: M = MilpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: out = set_fixed_variables(component_id='cipher_output_0_6', constraint_type='equal', bit_positions=range(32), bit_values=[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0])
            sage: trail = M.find_one_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, out])
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: M = MilpDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: out = set_fixed_variables(component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32), bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: trail = M.find_one_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, out]) # doctest: +SKIP
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpDeterministicTruncatedXorDifferentialModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80), bit_values=[0]*80)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(64), bit_values=[2,0,0,0] + [1,0,0,1] + [0,0,0,1] + [1,0,0,0] + [0] * 48)
            sage: trail = milp.find_one_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key]) # doctest: +SKIP
            ...

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("deterministic_truncated_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution

    def find_one_wordwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: M = MilpDeterministicTruncatedXorDifferentialModel(aes)
            sage: M.init_model_in_sage_milp_class()
            sage: trail = M.find_one_wordwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(aes))
            sage: trail['status']
            'SATISFIABLE'

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("wordwise_deterministic_truncated_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution

    def find_lowest_varied_patterns_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Return the solution representing a differential trail with the lowest number of unknown variables.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: M = MilpDeterministicTruncatedXorDifferentialModel(speck)
            sage: trail = M.find_lowest_varied_patterns_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
            sage: trail['total_weight']
            14.0


        """

        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p["probability"])

        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("deterministic_truncated_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution

    def find_lowest_varied_patterns_wordwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Return the solution representing a differential trail with the lowest number of unknown variables.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import MilpDeterministicTruncatedXorDifferentialModel
            sage: M = MilpDeterministicTruncatedXorDifferentialModel(aes)
            sage: M.init_model_in_sage_milp_class()
            sage: trail = M.find_lowest_varied_patterns_wordwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP


        """

        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p["probability"])

        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("wordwise_deterministic_truncated_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution


    @property
    def trunc_binvar(self):
        return self._trunc_binvar

    @property
    def trunc_wordvar(self):
        return self._trunc_wordvar

    @property
    def word_size(self):
        return self._word_size