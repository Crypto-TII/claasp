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
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints, fix_variables_value_deterministic_truncated_xor_differential_constraints
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import (
    update_dictionary_that_contains_wordwise_truncated_input_inequalities,
    output_dictionary_that_contains_wordwise_truncated_input_inequalities
)


class MilpWordwiseDeterministicTruncatedXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
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

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._model
            Mixed Integer Program (no objective, 0 variables, 0 constraints)
        """

        super().init_model_in_sage_milp_class(solver_name=SOLVER_DEFAULT)
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

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()

        """
        verbose_print("Building model in progress ...")

        mip = self._model
        x = self._binary_variable
        p = self._integer_variable


        components = self._cipher.get_all_components()
        last_component = components[-1]

        self.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_variables)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # objective is the number of unknown patterns i.e. tuples of the form (1, x)
        _, output_ids = last_component._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(p["probability"] == sum(x[output_msb] for output_msb in [id[0] for id in output_ids]))

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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
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

    def fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(self, fixed_variables=[]):
        """
        Returns a list of constraints that fix the input variables to a
        specific value.

        INPUTS:

        - ``model_variables`` -- *MIPVariable object*, the variable object of the model
        - ``fixed_variables`` -- *list of dict*, the variables to be fixed in
          standard format

          .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: cipher = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
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
        return fix_variables_value_deterministic_truncated_xor_differential_constraints(self, self.trunc_wordvar, fixed_variables)

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Model 1 from https://tosc.iacr.org/index.php/ToSC/article/view/8702/8294
        using the milp technique from https://github.com/Deterministic-TD-MDLA/auxiliary_material/blob/master/Supplementary-Material.pdf

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

        for component in self._cipher.get_all_components():
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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: M.init_model_in_sage_milp_class()
            sage: trail = M.find_one_wordwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(aes))
            ...
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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: M.init_model_in_sage_milp_class()
            sage: trail = M.find_lowest_varied_patterns_wordwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(aes)) # doctest: +SKIP
            ...
            sage: trail['total_weight']
            4.0


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
    def trunc_wordvar(self):
        return self._trunc_wordvar

    @property
    def word_size(self):
        return self._word_size