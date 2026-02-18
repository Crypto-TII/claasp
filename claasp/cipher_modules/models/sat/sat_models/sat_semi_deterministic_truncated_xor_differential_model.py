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
from claasp.cipher_modules.models.sat.sat_models.sat_truncated_xor_differential_model import (
    SatTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    SBOX,
    WORD_OPERATION,
)


def group_triples(var_names):
    """
    Given a list of variable names (strings) of the form
       hw_{p|q|r}_modadd_X_Y_Z
    group them by (X,Y,Z) and return a dict:
       grouped[(X, Y, Z)] = (pVarName, qVarName, rVarName)
    where pVarName, qVarName, rVarName are the corresponding names.
    We assume each group has exactly three variables: one for p, q, and r.
    """
    grouped = {}
    for name in var_names:
        if "hw_p_modadd" in name or "hw_q_modadd" in name or "hw_r_modadd" in name:
            parts = name.split("_")
            probability_component = parts[1]
            round_index = parts[3]
            component_index = parts[4]
            position_index = parts[5]
            key = (round_index, component_index, position_index)

            if key not in grouped:
                grouped[key] = {"p": None, "q": None, "r": None}
            grouped[key][probability_component] = name

    triples_dict = {}
    for k, bit_map in grouped.items():
        p_name = bit_map["p"]
        q_name = bit_map["q"]
        r_name = bit_map["r"]
        triples_dict[k] = (p_name, q_name, r_name)
    return triples_dict


class SatSemiDeterministicTruncatedXorDifferentialModel(SatTruncatedXorDifferentialModel):
    def __init__(self, cipher, counter="sequential", compact=False):
        super().__init__(cipher, counter, compact)

    def build_semi_deterministic_truncated_xor_differential_trail_model(
        self, number_of_unknowns_per_component=None, unknown_window_size_configuration=None, fixed_variables=[]
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
        operation_types = ("AND", "MODADD", "NOT", "OR", "ROTATE", "SHIFT", "XOR")

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.sat_semi_deterministic_truncated_xor_differential_constraints()
            else:
                print(f"{component.id} not yet implemented")

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if number_of_unknowns_per_component:
            self._build_unknown_variable_constraints(number_of_unknowns_per_component)

        if unknown_window_size_configuration is not None:
            variables, constraints = (
                SatSemiDeterministicTruncatedXorDifferentialModel.unknown_window_size_configuration_constraints(
                    unknown_window_size_configuration,
                    variables_list=self._variables_list,
                    cardinality_constraint_method=self._counter,
                )
            )
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

    def find_one_semi_deterministic_truncated_xor_differential_trail(
        self,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
        unknown_window_size_configuration=None,
        number_of_unknowns_per_component=None,
        options=None,
    ):
        """
        Returns one deterministic truncated XOR differential trail.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call
        - ``unknown_window_size_configuration`` -- *dict*, the number of maximum window sizes
        - ``number_of_unknowns_per_component`` -- *dict*, the number of unknowns per component
        """
        start_building_time = time.time()
        self.build_semi_deterministic_truncated_xor_differential_trail_model(
            fixed_variables=fixed_values,
            unknown_window_size_configuration=unknown_window_size_configuration,
            number_of_unknowns_per_component=number_of_unknowns_per_component,
        )

        end_building_time = time.time()
        solution = self.solve(DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL, solver_name=solver_name, options=options)
        solution["building_time_seconds"] = end_building_time - start_building_time

        return solution

    @staticmethod
    def unknown_window_size_configuration_constraints(
        unknown_window_size_configuration, variables_list=None, cardinality_constraint_method=None
    ):
        """
        Return lists of variables and constraints that fix the number of unknown
        variables of the input and the output of the trail to a specific value.

        INPUT:

        - ``unknown_window_size_configuration`` -- **dict**; the number of maximum window sizes
        - ``variables_list`` -- **list** (default: `None`); the list of variables of the SAT model.
        - ``cardinality_constraint_method`` -- **function** (default: `None`); the method to be used to generate the cardinality constraints.
        """

        new_variables_list = []
        new_constraints_list = []

        max_number_of_seq_window_size_0 = unknown_window_size_configuration["max_number_of_sequences_window_size_0"]
        max_number_of_seq_window_size_1 = unknown_window_size_configuration["max_number_of_sequences_window_size_1"]
        max_number_of_seq_window_size_2 = unknown_window_size_configuration["max_number_of_sequences_window_size_2"]

        hw_variables = [var_id for var_id in variables_list if var_id.startswith("hw_")]

        def x_iff_abc_cnf(a: str, b: str, c: str, x: str) -> list:
            """
            Generate CNF clauses for x <-> (a and b and c).

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
                f"{negate(x)} {a}",
                f"{negate(x)} {b}",
                f"{negate(x)} {c}",
                f"{negate(a)} {negate(b)} {negate(c)} {x}",
            ]
            return clauses

        triples_dict = group_triples(hw_variables)

        window_1_vars = []
        window_2_vars = []
        for tuple_key, tuple_value in triples_dict.items():
            window_1_var = "hw_window_1_" + "_".join(tuple_key)
            window_1_vars.append(window_1_var)
            constraints = x_iff_abc_cnf(tuple_value[0], "-" + tuple_value[1], tuple_value[2], window_1_var)

            new_variables_list.extend([window_1_var])
            new_constraints_list.extend(constraints)

            window_2_var = "hw_window_2_" + "_".join(tuple_key)
            window_2_vars.append(window_2_var)
            constraints = x_iff_abc_cnf(tuple_value[0], "-" + tuple_value[1], "-" + tuple_value[2], window_2_var)
            new_variables_list.extend([window_2_var])
            new_constraints_list.extend(constraints)
        cardinality_variables_window_1, cardinality_constraints_window_1 = cardinality_constraint_method(
            window_1_vars, max_number_of_seq_window_size_1
        )

        new_constraints_list.extend(cardinality_constraints_window_1)
        new_variables_list.extend(cardinality_variables_window_1)

        cardinality_variables_window_2, cardinality_constraints_window_2 = cardinality_constraint_method(
            window_2_vars, max_number_of_seq_window_size_2
        )
        new_constraints_list.extend(cardinality_constraints_window_2)
        new_variables_list.extend(cardinality_variables_window_2)

        return new_variables_list, new_constraints_list

    @staticmethod
    def _calculate_component_weight(component, variable2value, variables_list):
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
                sub_dict = {triplet: dict1.get(triplet, None) for triplet in triplets}
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
        if (
            "MODSUB" in component.description
            or "MODADD" in component.description
            or "AND" in component.description
            or "OR" in component.description
            or SBOX in component.type
        ):
            hw_variables = [var_id for var_id in variables_list if var_id.startswith("hw_")]
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
            weight = SatSemiDeterministicTruncatedXorDifferentialModel._calculate_component_weight(
                component, variable2value, self._variables_list
            )
            total_weight += weight
            component_solution = set_component_solution(value, weight)

            components_solutions[f"{component.id}"] = component_solution

        return components_solutions, total_weight
