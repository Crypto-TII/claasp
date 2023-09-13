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
from claasp.cipher_modules.models.milp.utils.utils import fix_variables_value_deterministic_truncated_xor_differential_constraints
from claasp.cipher_modules.models.milp.milp_model import MilpModel, verbose_print
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION, LINEAR_LAYER, SBOX, MIX_COLUMN)


class MilpBitwiseDeterministicTruncatedXorDifferentialModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)
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
        verbose_print("Building model in progress ...")

        mip = self._model
        x = self._binary_variable
        p = self._integer_variable


        components = self._cipher.get_all_components()
        last_component = components[-1]

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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_bitwise_deterministic_truncated_xor_differential_constraints(
            fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, SBOX, MIX_COLUMN,
                               WORD_OPERATION]
            operation = component.description[0]
            operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR']

            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                if operation in ['XOR','MODADD']:
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
             x_6 <= 6 - 3*x_4 - 3*x_5,
            ...
            -2 + 3*x_13 - 3*x_14 <= x_15,
            x_4 + x_7 + x_10 + x_13 == 1]


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

    def find_one_bitwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
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
        verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        mip.set_objective(None)
        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve("bitwise_deterministic_truncated_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution

    def find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
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
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: M = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: trail = M.find_lowest_varied_patterns_bitwise_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
            ...
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
        solution = self.solve("bitwise_deterministic_truncated_xor_differential", solver_name)
        solution['building_time'] = building_time

        return solution

    @property
    def trunc_binvar(self):
        return self._trunc_binvar
