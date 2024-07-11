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
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_BITWISE_DETERMINISTIC_TRUNCATED, \
    MILP_BACKWARD_SUFFIX, MILP_BUILDING_MESSAGE, MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE
from claasp.cipher_modules.models.milp.utils.milp_truncated_utils import \
    fix_variables_value_deterministic_truncated_xor_differential_constraints
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)


class MilpBitwiseDeterministicTruncatedXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        super().__init__(cipher, n_window_heuristic, verbose)
        self._trunc_binvar = None

    def init_model_in_sage_milp_class(self, solver_name=SOLVER_DEFAULT):
        """
        Initialize a MILP instance from the build-in sage class.

        INPUT:

        - ``solver_name`` -- **string**; the solver to call

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp._model
            Mixed Integer Program (no objective, 0 variables, 0 constraints)
        """

        super().init_model_in_sage_milp_class(solver_name=SOLVER_DEFAULT)
        self._trunc_binvar = self._model.new_variable(integer=True, nonnegative=True)
        self._model.set_max(self._trunc_binvar, 2)

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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()

        """
        self._verbose_print(MILP_BUILDING_MESSAGE)

        mip = self._model
        x = self._binary_variable
        p = self._integer_variable


        components = self._cipher.get_all_components()
        last_component = components[-1]

        self.build_bitwise_deterministic_truncated_xor_differential_trail_model(fixed_variables)
        for index, constraint in enumerate(self._model_constraints):
            mip.add_constraint(constraint)

        # objective is the number of unknown patterns i.e. tuples of the form (1, x)

        input_id_tuples, output_id_tuples = last_component._get_input_output_variables_tuples()
        input_ids, output_ids = last_component._get_input_output_variables()
        linking_constraints = self.link_binary_tuples_to_integer_variables(input_id_tuples + output_id_tuples,
                                                                           input_ids + output_ids)
        for constraint in linking_constraints:
            mip.add_constraint(constraint)
        mip.add_constraint(p[MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE] == sum(x[output_msb] for output_msb in [id[0] for id in output_id_tuples]))


    def build_bitwise_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[], component_list=None):
        """
        Build the model for the search of bitwise deterministic truncated XOR differential trails.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format
        - ``component_list`` -- **list** (default: `[]`); cipher component objects to be included in the model

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_bitwise_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_bitwise_deterministic_truncated_xor_differential_constraints(
            fixed_variables)
        self._model_constraints = constraints

        component_list = component_list or self._cipher.get_all_components()
        for component in component_list:
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                               WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                if operation in ['XOR','MODADD'] or component.type == LINEAR_LAYER:
                    variables, constraints = component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(self)
                elif component.type == SBOX:
                    variables, constraints = component.milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints(self)
                else:
                    variables, constraints = component.milp_bitwise_deterministic_truncated_xor_differential_constraints(self)

            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def fix_variables_value_bitwise_deterministic_truncated_xor_differential_constraints(self, fixed_variables=[]):
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

            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(simon)
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
            sage: constraints = milp.fix_variables_value_bitwise_deterministic_truncated_xor_differential_constraints(fixed_variables)
            sage: constraints
            [x_0 == 1,
             x_1 == 0,
             x_2 == 1,
             x_3 == 1,
             x_5 <= 6 - 6*x_4,
            ...
             -2 <= x_11,
             x_4 + x_6 + x_8 + x_10 == 1]


        """

        return fix_variables_value_deterministic_truncated_xor_differential_constraints(self, self.trunc_binvar, fixed_variables)

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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(fancy)
            sage: milp.init_model_in_sage_milp_class()
            sage: component = fancy.component_from(0, 6)
            sage: input_ids, output_ids = component._get_input_output_variables()
            sage: input_ids_tuples, output_ids_tuples = component._get_input_output_variables_tuples()
            sage: constraints = milp.link_binary_tuples_to_integer_variables(input_ids_tuples + output_ids_tuples, input_ids + output_ids)
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

    def find_one_bitwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: trail = M.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: out = set_fixed_variables(component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32), bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: trail = M.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, out]) # doctest: +SKIP
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=1)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(present)
            sage: milp.init_model_in_sage_milp_class()
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80), bit_values=[0]*80)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(64), bit_values=[2,0,0,0] + [1,0,0,1] + [0,0,0,1] + [1,0,0,0] + [0] * 48)
            sage: trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key]) # doctest: +SKIP
            ...

        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_DETERMINISTIC_TRUNCATED, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    def find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return the solution representing a differential trail with the lowest number of unknown variables.

        INPUTS:

        - ``solver_name`` -- *str*, the solver to call
        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: trail = M.find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
            ...
            sage: trail['total_weight']
            14.0


        """

        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p[MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE])

        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_BITWISE_DETERMINISTIC_TRUNCATED, solver_name, external_solver_name)
        solution['building_time'] = building_time

        return solution

    @property
    def trunc_binvar(self):
        return self._trunc_binvar

    def _get_component_values(self, objective_variables, components_variables):
        components_values = {}
        list_component_ids = self._cipher.inputs + self._cipher.get_all_components_ids()
        for component_id in list_component_ids:
            dict_tmp = self._get_component_value_weight(component_id, components_variables)
            components_values[component_id] = dict_tmp
        return components_values
    def _parse_solver_output(self):
        mip = self._model
        components_variables = mip.get_values(self._trunc_binvar)
        objective_variables = mip.get_values(self._integer_variable)
        objective_value = objective_variables[MILP_TRUNCATED_XOR_DIFFERENTIAL_OBJECTIVE]
        components_values = self._get_component_values(objective_variables, components_variables)

        return objective_value, components_values

    def _get_component_value_weight(self, component_id, components_variables):

        if component_id in self._cipher.inputs:
            output_size = self._cipher.inputs_bit_size[self._cipher.inputs.index(component_id)]
        else:
            component = self._cipher.get_component_from_id(component_id)
            output_size = component.output_bit_size
        suffix_dict = {"": output_size}
        final_output = self._get_final_output(component_id, components_variables, suffix_dict)
        if len(final_output) == 1:
            final_output = final_output[0]

        return final_output

    def _get_final_output(self, component_id, components_variables, suffix_dict):
        final_output = []
        for suffix in suffix_dict.keys():
            diff_str = ""
            for i in range(suffix_dict[suffix]):
                if component_id + "_" + str(i) + suffix in components_variables:
                    bit = components_variables[component_id + "_" + str(i) + suffix]
                    if bit < 2:
                        diff_str += f"{bit}".split(".")[0]
                    else:
                        diff_str += "?"
                else:
                    diff_str += "*"
            final_output.append(set_component_solution(diff_str))

        return final_output


