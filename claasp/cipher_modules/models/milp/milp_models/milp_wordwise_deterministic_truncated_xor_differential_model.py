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
from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_WORDWISE_DETERMINISTIC_TRUNCATED, \
    MILP_BUILDING_MESSAGE, MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints, \
    _get_variables_values_as_string
from claasp.cipher_modules.models.milp.utils.milp_truncated_utils import \
    fix_variables_value_deterministic_truncated_xor_differential_constraints
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import (
    update_dictionary_that_contains_wordwise_truncated_input_inequalities,
    output_dictionary_that_contains_wordwise_truncated_input_inequalities
)
from claasp.editor import get_output_bit_size_from_id
from numpy import array_split


class MilpWordwiseDeterministicTruncatedXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        super().__init__(cipher, n_window_heuristic, verbose)
        self._trunc_wordvar = None
        self._word_size = 4
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

    def add_constraints_to_build_in_sage_milp_class(self, fixed_bits=[], fixed_words=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        INPUT:

        - ``model_type`` -- **string**; the model to solve
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)

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
        self._verbose_print(MILP_BUILDING_MESSAGE)

        mip = self._model
        x = self._binary_variable
        p = self._integer_variable


        components = self._cipher.get_all_components()
        last_component = components[-1]

        self.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_bits, fixed_words)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # objective is the number of unknown patterns i.e. tuples of the form (1, x)
        _, output_ids = last_component._get_wordwise_input_output_linked_class_tuples(self)
        mip.add_constraint(p[MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE] == sum(x[output_msb] for output_msb in [id[0] for id in output_ids]))

    def build_wordwise_deterministic_truncated_xor_differential_trail_model(self, fixed_bits=[], fixed_words=[], cipher_list=None):
        """
        Build the model for the search of wordwise deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``cipher_list`` -- **list** (default: `[]`); cipher objects to be included in the model

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(16),
                                    bit_values=[0, 1, 0, 3] + [0] * 12)
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(128),
                              bit_values=[0] * 128)
            sage: milp.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_bits=[key], fixed_words=[plaintext])
            ...
        """
        self._variables_list = []
        cipher_list = cipher_list or [self._cipher]
        component_list = [c for cipher_component in [cipher.get_all_components() for cipher in cipher_list] for c in cipher_component]
        variables, constraints = self.input_wordwise_deterministic_truncated_xor_differential_constraints(component_list)
        constraints += self.fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(fixed_bits, fixed_words, cipher_list)
        self._model_constraints = constraints

        for component in component_list:
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                               WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

            if component.type in component_types or operation in operation_types:
                variables, constraints = component.milp_wordwise_deterministic_truncated_xor_differential_constraints(self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def fix_variables_value_wordwise_deterministic_truncated_xor_differential_constraints(self,  fixed_bits=[], fixed_words=[], cipher_list=None):
        """
        Returns a list of constraints that fix the input variables to a
        specific value.
        If some bit variables are set to 0, the corresponding word (if it exists) is also set to 0.

        INPUTS:

        - ``model_variables`` -- *MIPVariable object*, the variable object of the model
        - ``fixed_bits`` -- *list of dict*, the bitwise variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``fixed_words`` -- *list of dict*, the wordwise variables to be fixed in
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
             x_10 == x_11,
             1 <= x_4 + x_6 + x_8 + x_10]


        """
        x = self.trunc_wordvar
        constraints = self.fix_variables_value_constraints(fixed_bits)
        cipher_list = cipher_list or [self._cipher]
        for fixed_variable in fixed_bits:
            if fixed_variable["constraint_type"] == "equal":
                output_bit_size = get_output_bit_size_from_id(cipher_list, fixed_variable["component_id"])
                for i, current_word_bits in enumerate(array_split(range(output_bit_size), output_bit_size // self._word_size)):
                    if set(current_word_bits) <= set(fixed_variable["bit_positions"]):
                        if sum([fixed_variable["bit_values"][fixed_variable["bit_positions"].index(_)] for _ in
                                current_word_bits]) == 0:
                            constraints.append(x[f'{fixed_variable["component_id"]}_word_{i}_class'] == 0)

        return constraints + fix_variables_value_deterministic_truncated_xor_differential_constraints(self, x,
                                                                                                      fixed_words)

    def input_wordwise_deterministic_truncated_xor_differential_constraints(self, component_list=None):
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

        component_list = component_list or self._cipher.get_all_components()

        update_dictionary_that_contains_wordwise_truncated_input_inequalities(self._word_size)
        dict_inequalities = output_dictionary_that_contains_wordwise_truncated_input_inequalities()
        inequalities = dict_inequalities[self._word_size]

        for component in component_list:
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

    def find_one_wordwise_deterministic_truncated_xor_differential_trail(self, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(16), bit_values=[0,1,0,3] + [0] * 12)
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(128), bit_values=[0]*128)
            sage: trail = M.find_one_wordwise_deterministic_truncated_xor_differential_trail(fixed_bits=[key], fixed_words=[plaintext])
            ...
            sage: trail['status']
            'SATISFIABLE'
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_DETERMINISTIC_TRUNCATED, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_lowest_varied_patterns_wordwise_deterministic_truncated_xor_differential_trail(self, fixed_bits=[], fixed_words=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return the solution representing a differential trail with the lowest number of unknown variables.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_bits`` -- *list of dict*, the bit variables to be fixed in standard format
        - ``fixed_words`` -- *list of dict*, the word variables to be fixed in standard format
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

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
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p[MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE])

        self.add_constraints_to_build_in_sage_milp_class(fixed_bits, fixed_words)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_WORDWISE_DETERMINISTIC_TRUNCATED, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution


    @property
    def trunc_wordvar(self):
        return self._trunc_wordvar

    @property
    def word_size(self):
        return self._word_size


    def _get_component_values(self, objective_variables, components_variables):
        components_values = {}
        list_component_ids = self._cipher.inputs + self._cipher.get_all_components_ids()
        for component_id in list_component_ids:
            dict_tmp = self._get_component_value_weight(component_id, components_variables)
            components_values[component_id] = dict_tmp
        return components_values
    def _parse_solver_output(self):
        mip = self._model
        components_variables = mip.get_values(self._trunc_wordvar)
        objective_variables = mip.get_values(self._integer_variable)
        objective_value = objective_variables[MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE]
        components_values = self._get_component_values(objective_variables, components_variables)

        return objective_value, components_values

    def _get_component_value_weight(self, component_id, components_variables):

        wordsize = self._word_size
        if component_id in self._cipher.inputs:
            output_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(component_id)] // wordsize
        else:
            component = self._cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size // wordsize
        suffix_dict = {"_class": output_size}
        final_output = self._get_final_output(component_id, components_variables, suffix_dict)
        if len(final_output) == 1:
            final_output = final_output[0]

        return final_output

    def _get_final_output(self, component_id, components_variables, suffix_dict):
        final_output = []
        for suffix in suffix_dict.keys():
            diff_str = _get_variables_values_as_string(component_id + "_word", components_variables, suffix,
                                                            suffix_dict[suffix])
            final_output.append(set_component_solution(diff_str))

        return final_output