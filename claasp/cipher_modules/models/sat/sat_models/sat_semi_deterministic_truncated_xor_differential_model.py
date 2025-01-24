
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

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import (CIPHER_OUTPUT, CONSTANT, DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL,
                                  INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION)


def group_triples(var_names):
    """
    Given a list of variable names (strings) of the form
       hw_{p|q|r}_modadd_X_Y_Z_W
    group them by (X,Y,Z,W) and return a dict:
       grouped[(X, Y, Z, W)] = (pVarName, qVarName, rVarName)
    where pVarName, qVarName, rVarName are the corresponding names.
    We assume each group has exactly three variables: one for p, q, and r.
    """
    grouped = {}
    for name in var_names:
        # Example name: "hw_p_modadd_0_1_0_0"
        # Split by '_'
        parts = name.split('_')
        # parts[1] = 'p' or 'q' or 'r'
        # the block parts[3], parts[4], parts[5] correspond to X, Y, Z
        # possibly parts[6] is W (if present)

        bit_id = parts[1]  # 'p', 'q', or 'r'

        # we expect something like: parts = ["hw", "p", "modadd", X, Y, Z, W]
        # e.g. "hw_p_modadd_0_1_3_0"
        X = parts[3]
        Y = parts[4]
        Z = parts[5]
        W = parts[6] if len(parts) > 6 else "0"  # sometimes there's an extra index

        key = (X, Y, Z, W)

        if key not in grouped:
            grouped[key] = {'p': None, 'q': None, 'r': None}
        grouped[key][bit_id] = name

    # Convert the dictionary of bit_id->name into a tuple (pName, qName, rName)
    # for easier use later:
    triples_dict = {}
    for k, bit_map in grouped.items():
        # each bit_map is e.g. {'p': 'hw_p_modadd_...', 'q': 'hw_q_modadd_...', 'r': 'hw_r_modadd_...'}
        p_name = bit_map['p']
        q_name = bit_map['q']
        r_name = bit_map['r']
        triples_dict[k] = (p_name, q_name, r_name)

    return triples_dict

class SatSemiDeterministicTruncatedXorDifferentialModel(SatModel):
    def __init__(self, cipher, counter='sequential', compact=False):
        super().__init__(cipher, counter, compact)

    def build_semi_deterministic_truncated_xor_differential_trail_model(
            self, number_of_unknown_variables=None, weight=None, fixed_variables=[]
    ):
        """
        Build the model for the search of deterministic truncated XOR DIFFERENTIAL trails.

        INPUT:

        - ``number_of_unknown_variables`` -- **int** (default: None); the number
          of unknown variables that we want to have in the trail
        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be
          fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=2)
            sage: sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: sat.build_semi_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        variables = []
        constraints = SatSemiDeterministicTruncatedXorDifferentialModel.fix_variables_value_constraints(fixed_variables)
        self._variables_list = []
        self._model_constraints = constraints
        component_types = (CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION)
        operation_types = ('AND', 'MODADD', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'XOR')

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.sat_semi_deterministic_truncated_xor_differential_constraints()
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        # if number_of_unknown_variables is not None:
        #    variables, constraints = self.weight_constraints(number_of_unknown_variables)
        #    self._variables_list.extend(variables)
        #    self._model_constraints.extend(constraints)

        if weight is not None:
            variables, constraints = self.weight_constraints(number_of_unknown_variables)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)


    @staticmethod
    def fix_variables_value_constraints(fixed_variables=[]):
        """
        Return constraints for fixed variables

        Return lists of variables and clauses for fixing variables in semi
        deterministic truncated XOR differential model.

        .. SEEALSO::

           :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'ciphertext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [2, 1, 1, 0]
            ....: }]
            sage: SatSemiDeterministicTruncatedXorDifferentialModel.fix_variables_value_constraints(fixed_variables)
            ['-plaintext_0_0',
             'plaintext_0_1',
             '-plaintext_1_0',
             '-plaintext_1_1',
             '-plaintext_2_0',
             'plaintext_2_1',
             '-plaintext_3_0',
             'plaintext_3_1',
             '-ciphertext_0_0 ciphertext_1_0 -ciphertext_1_1 ciphertext_2_0 -ciphertext_2_1 ciphertext_3_0 ciphertext_3_1']
        """
        constraints = []
        for variable in fixed_variables:
            component_id = variable['component_id']
            is_equal = (variable['constraint_type'] == 'equal')
            bit_positions = variable['bit_positions']
            bit_values = variable['bit_values']
            variables_ids = []
            for position, value in zip(bit_positions, bit_values):
                false_sign = '-' * is_equal
                true_sign = '-' * (not is_equal)
                if value == 0:
                    variables_ids.append(f'{false_sign}{component_id}_{position}_0')
                    variables_ids.append(f'{false_sign}{component_id}_{position}_1')
                elif value == 1:
                    variables_ids.append(f'{false_sign}{component_id}_{position}_0')
                    variables_ids.append(f'{true_sign}{component_id}_{position}_1')
                elif value == 2:
                    #import ipdb; ipdb.set_trace()
                    variables_ids.append(f'{true_sign}{component_id}_{position}_0')
            if is_equal:
                constraints.extend(variables_ids)
            else:
                constraints.append(' '.join(variables_ids))

        return constraints

    def find_one_semi_deterministic_truncated_xor_differential_trail(
            self,
            fixed_values=[],
            solver_name=solvers.SOLVER_DEFAULT,
            unknown_probability_weight_configuration=None
    ):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: M = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: trail = M.find_one_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: M = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0]*64)
            sage: out = set_fixed_variables(component_id='cipher_output_2_12', constraint_type='equal', bit_positions=range(32), bit_values=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            sage: trail = M.find_one_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key, out]) # doctest: +SKIP
            ...

            sage: from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
            sage: from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
            sage: present = PresentBlockCipher(number_of_rounds=1)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: sat = SatSemiDeterministicTruncatedXorDifferentialModel(present)
            sage: key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(80), bit_values=[0]*80)
            sage: plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(64), bit_values=[2,0,0,0] + [1,0,0,1] + [0,0,0,1] + [1,0,0,0] + [0] * 48)
            sage: trail = sat.find_one_semi_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key]) # doctest: +SKIP
            ...

        """
        start_building_time = time.time()
        self.build_semi_deterministic_truncated_xor_differential_trail_model(fixed_variables=fixed_values)
        if unknown_probability_weight_configuration is not None:
            self.weight_constraints(unknown_probability_weight_configuration)

        end_building_time = time.time()
        solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time

        return solution

    def find_lowest_varied_patterns_semi_deterministic_truncated_xor_differential_trail(self, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Return the solution representing a differential trail with the lowest number of unknown variables.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: S = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: trail = S.find_lowest_varied_patterns_semi_deterministic_truncated_xor_differential_trail(get_single_key_scenario_format_for_fixed_values(speck))
            sage: trail['status']
            'SATISFIABLE'

        .. SEEALSO::

            :ref:`sat-solvers`
        """
        current_unknowns_count = 1
        start_building_time = time.time()
        self.build_semi_deterministic_truncated_xor_differential_trail_model(
            number_of_unknown_variables=current_unknowns_count, fixed_variables=fixed_values)
        end_building_time = time.time()
        solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']
        while solution['status'] != 'SATISFIABLE':
            current_unknowns_count += 1
            start_building_time = time.time()
            self.build_semi_deterministic_truncated_xor_differential_trail_model(
                number_of_unknown_variables=current_unknowns_count, fixed_variables=fixed_values)
            end_building_time = time.time()
            solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name)
            solution['building_time_seconds'] = end_building_time - start_building_time
            total_time += solution['solving_time_seconds']
            max_memory = max((max_memory, solution['memory_megabytes']))
        solution['solving_time_seconds'] = total_time
        solution['memory_megabytes'] = max_memory

        return solution

    def weight_constraints(self, configuration):
        """
        Return lists of variables and constraints that fix the number of unknown
        variables of the input and the output of the trail to a specific value.

        INPUT:

        - ``number_of_unknown_variables`` -- **int**; the number of the unknown variables

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: sat.build_semi_deterministic_truncated_xor_differential_trail_model()
            sage: sat.weight_constraints(4)
            (['dummy_hw_0_0_0',
              'dummy_hw_0_0_1',
              'dummy_hw_0_0_2',
              ...
              '-dummy_hw_0_61_3 dummy_hw_0_62_3',
              '-cipher_output_2_12_30_0 -dummy_hw_0_61_3',
              '-cipher_output_2_12_31_0 -dummy_hw_0_62_3'])
        """

        max_number_of_sequences_window_size_0 = configuration['max_number_of_sequences_window_size_0']
        max_number_of_sequences_window_size_1 = configuration['max_number_of_sequences_window_size_1']
        max_number_of_sequences_window_size_2 = configuration['max_number_of_sequences_window_size_2']

        hw_variables = [var_id for var_id in self._variables_list if var_id.startswith('hw_')]

        def x_iff_abc_cnf(a: str, b: str, c: str, x: str) -> list:
            """
            Generate CNF clauses for x <-> a, b, c.

            Args:
                a, b, c: Strings representing boolean variables (can include negations with '-').
                x: String representing the boolean variable x (can include negations with '-').

            Returns:
                List of CNF clauses in f-string format where OR is represented by space and negations by '-'.
            """

            def negate(var):
                """Return the negated form of a variable."""
                return var[1:] if var.startswith("-") else f"-{var}"

            clauses = [
                f"{negate(x)} {a}",  # -x OR a
                f"{negate(x)} {b}",  # -x OR b
                f"{negate(x)} {c}",  # -x OR c
                f"{negate(a)} {negate(b)} {negate(c)} {x}"  # -a OR -b OR -c OR x
            ]
            return clauses

        triples_dict = group_triples(hw_variables)
        window_1_vars = []
        window_2_vars = []
        for tuple_key, tuple_value in triples_dict.items():
            window_1_var = "hw_window_1" + "_".join(tuple_key)
            window_1_vars.append(window_1_var)
            constraints = x_iff_abc_cnf(
                tuple_value[0], "-" + tuple_value[1], tuple_value[2], window_1_var
            )
            # import ipdb; ipdb.set_trace()
            self._variables_list.extend([window_1_var])
            self._model_constraints.extend(constraints)

            window_2_var = "hw_window_2" + "_".join(tuple_key)
            window_2_vars.append(window_2_var)
            constraints = x_iff_abc_cnf(
                tuple_value[0], "-" + tuple_value[1], "-" + tuple_value[2], window_2_var
            )
            self._variables_list.extend([window_2_var])
            self._model_constraints.extend(constraints)
        cardinality_variables_window_1, cardinality_constraints_window_1 = self._counter(
            window_1_vars, max_number_of_sequences_window_size_1
        )
        self._model_constraints.extend(cardinality_constraints_window_1)
        self._variables_list.extend(cardinality_variables_window_1)
        cardinality_variables_window_2, cardinality_constraints_window_2 = self._counter(
            window_2_vars, max_number_of_sequences_window_size_2
        )
        self._model_constraints.extend(cardinality_constraints_window_2)
        self._variables_list.extend(cardinality_variables_window_2)

    def _calculate_component_weight(self, component, variable2value):
        def map_dicts(dict1, dict2):
            """
            Map values from dict1 to keys defined in dict2.

            Args:
                dict1 (dict): A dictionary containing keys and their corresponding values.
                dict2 (dict): A dictionary where keys are tuples and values are tuples of keys from dict1.

            Returns:
                dict: A dictionary where each key from dict2 maps to a sub-dictionary of values from dict1.
            """
            result = {}

            for key, triplets in dict2.items():
                # Create a sub-dictionary for each key in dict2
                try:
                    sub_dict = {triplet: dict1.get(triplet, None) for triplet in triplets}
                except:
                    import ipdb;
                    ipdb.set_trace()
                result[key] = sub_dict

            return result

        def get_probability_expressions(input_dict):
            """
            Process the input dictionary and calculate the number of times
            each (P, Q, R) combination occurs.

            Args:
                input_dict (dict): A dictionary where each key is a tuple,
                                   and values are dictionaries with keys P, Q, R.

            Returns:
                dict: A dictionary where keys are decimal equivalents of binary
                      representations (P, Q, R), and values are the counts of occurrences.
            """
            # Initialize a dictionary to store counts for each combination
            counts = {0: 0, 4: 0, 9: 0, 19: 0, 41: 0, 100: 0}

            # Iterate over the input dictionary
            for key, values in input_dict.items():
                # Extract the values of P, Q, R
                if list(values.keys()) == [None] and list(values.values()) == [None]:
                    continue

                p = next((v for k, v in values.items() if "p_modadd" in k), None)
                q = next((v for k, v in values.items() if "q_modadd" in k), None)
                r = next((v for k, v in values.items() if "r_modadd" in k), None)

                # Ensure all three are present
                if p is not None and q is not None and r is not None:
                    # Convert P, Q, R to binary and calculate decimal equivalent
                    binary = f"{p}{q}{r}"
                    decimal = int(binary, 2)

                    # Map binary decimal equivalent to the desired output format
                    decimal_map = {
                        0: 0,  # 000
                        1: 4,  # 001
                        2: 9,  # 010
                        3: 19,  # 011
                        4: 41,  # 100
                        5: 100,  # 101
                    }

                    # Increment the count for the mapped value
                    if decimal in decimal_map:
                        counts[decimal_map[decimal]] += 1

            return counts

        weight = 0
        if ('MODSUB' in component.description or 'MODADD' in component.description or 'AND' in component.description
                or 'OR' in component.description or SBOX in component.type):

            hw_variables = [var_id for var_id in self._variables_list if var_id.startswith('hw_')]
            hw_variables = [var_id for var_id in hw_variables if component.id in var_id]
            triples_dict = group_triples(hw_variables)

            result_triples = map_dicts(variable2value, triples_dict)
            probability_counts = get_probability_expressions(result_triples)

            for key, value in probability_counts.items():
                weight += value * (key / 100)

        return weight


    def _parse_solver_output(self, variable2value):
        components_solutions = self._get_cipher_inputs_components_solutions_double_ids(variable2value)
        total_weight = 0
        for component in self._cipher.get_all_components():
            value = self._get_component_value_double_ids(component, variable2value)
            weight = self._calculate_component_weight(component, variable2value)
            total_weight += weight
            component_solution = set_component_solution(value, weight)
            components_solutions[f'{component.id}'] = component_solution

        return components_solutions, total_weight
