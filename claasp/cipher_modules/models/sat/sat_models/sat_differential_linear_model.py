import time

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import (
    SatBitwiseDeterministicTruncatedXorDifferentialModel
)
from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import \
    SatSemiDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.cipher_modules.models.sat.utils import utils as sat_utils, constants
from claasp.cipher_modules.models.utils import set_component_solution, get_bit_bindings


class SatDifferentialLinearModel(SatModel):
    """
    Model that combines concrete XOR differential model with bitwise deterministic truncated differential model
    and linear model to create a differential-linear model.
    """

    def __init__(self, cipher, dict_of_components):
        """
        Initializes the model with cipher and components.

        INPUT:
        - ``cipher`` -- **object**; The cipher model used in the SAT-based differential trail search.
        - ``dict_of_components`` -- **dict**; Dictionary mapping component IDs to their respective models and types.
        """
        self.dict_of_components = dict_of_components
        self.regular_components = self._get_components_by_type('sat_xor_differential_propagation_constraints')

        model_types = set(component['model_type'] for component in self.dict_of_components)

        truncated_model_types = {
            item for item in model_types if
            item != 'sat_xor_differential_propagation_constraints' and item != 'sat_xor_linear_mask_propagation_constraints'
        }

        allow_truncated_models_types = {
            'sat_semi_deterministic_truncated_xor_differential_constraints',
            'sat_bitwise_deterministic_truncated_xor_differential_constraints'
        }

        if len(truncated_model_types & allow_truncated_models_types) == 0 or len(
                truncated_model_types & allow_truncated_models_types) == 2:
            raise ValueError(f"Model types should be one of {allow_truncated_models_types}")

        self.truncated_model_type = list(truncated_model_types)[0]
        self.truncated_components = self._get_components_by_type(self.truncated_model_type)
        self.linear_components = self._get_components_by_type(
            'sat_xor_linear_mask_propagation_constraints')
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, '_'.join)
        super().__init__(cipher, "sequential", False)

    def _get_components_by_type(self, model_type):
        """
        Retrieves components based on their model type.

        INPUT:
        - ``model_type`` -- **str**; The model type to filter components.

        RETURN:
        - **list**; A list of components of the specified type.
        """
        return [component for component in self.dict_of_components if component['model_type'] == model_type]

    def _get_regular_xor_differential_components_in_border(self):
        """
        Retrieves regular components that are connected to truncated components (border components).

        RETURN:
        - **list**; A list of regular components at the border.
        """
        regular_component_ids = {item['component_id'] for item in self.regular_components}
        border_components = []

        for truncated_component in self.truncated_components:
            component_obj = self.cipher.get_component_from_id(truncated_component['component_id'])
            for input_id in component_obj.input_id_links:
                if input_id in regular_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_truncated_xor_differential_components_in_border(self):
        """
        Retrieves truncated components that are connected to linear components (border components).

        RETURN:
        - **list**; A list of truncated components at the border.
        """
        truncated_component_ids = {item['component_id'] for item in self.truncated_components}
        border_components = []
        print("truncated_component_ids:", truncated_component_ids)
        print("linear_component_ids:", [item['component_id'] for item in self.linear_components])

        for linear_component in self.linear_components:
            component_obj = self.cipher.get_component_from_id(linear_component['component_id'])
            for input_id in component_obj.input_id_links:
                if input_id in truncated_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_connecting_constraints(self):
        """
        Adds constraints for connecting regular, truncated, and linear components.
        """
        def is_any_string_in_list_substring_of_string(string, string_list):
            # Check if any string in the list is a substring of the given string
            return any(s in string for s in string_list)

        border_components = self._get_regular_xor_differential_components_in_border()
        for component_id in border_components:
            component = self.cipher.get_component_from_id(component_id)
            for idx in range(component.output_bit_size):
                constraints = sat_utils.get_cnf_bitwise_truncate_constraints(
                    f'{component_id}_{idx}', f'{component_id}_{idx}_0', f'{component_id}_{idx}_1'
                )
                self._model_constraints.extend(constraints)
                self._variables_list.extend([
                    f'{component_id}_{idx}', f'{component_id}_{idx}_0', f'{component_id}_{idx}_1'
                ])

        border_components = self._get_truncated_xor_differential_components_in_border()

        linear_component_ids = [item['component_id'] for item in self.linear_components]

        for component_id in border_components:
            component = self.cipher.get_component_from_id(component_id)
            for idx in range(component.output_bit_size):
                truncated_component = f'{component_id}_{idx}_o'
                component_successors = self.bit_bindings[truncated_component]
                for component_successor in component_successors:
                    length_component_successor = len(component_successor)
                    component_successor_id = component_successor[:length_component_successor-2]

                    if is_any_string_in_list_substring_of_string(component_successor_id, linear_component_ids):
                        constraints = sat_utils.get_cnf_truncated_linear_constraints(
                            component_successor, f'{component_id}_{idx}_0'
                        )
                        self._model_constraints.extend(constraints)
                        self._variables_list.extend([component_successor, f'{component_id}_{idx}_0'])

    def _build_weight_constraints(self, weight):
        """
        Builds weight constraints for the model based on the specified weight.

        INPUT:
        - ``weight`` -- **int**; The weight to constrain the search. If set to 0, the hardware variables are negated.

        RETURN:
        - **tuple**; A tuple containing a list of variables and a list of constraints.
        """

        hw_variables = [var_id for var_id in self._variables_list if var_id.startswith('hw_')]

        linear_component_ids = [linear_component["component_id"] for linear_component in self.linear_components]
        hw_linear_variables = []
        for linear_component_id in linear_component_ids:
            for hw_variable in hw_variables:
                if linear_component_id in hw_variable:
                    hw_linear_variables.append(hw_variable)
        hw_variables.extend(hw_linear_variables)
        if weight == 0:
            return [], [f'-{var}' for var in hw_variables]

        return self._counter(hw_variables, weight)

    def _build_unknown_variable_constraints(self, num_unknowns):
        """
        Adds constraints for limiting the number of unknown variables.

        INPUT:
        - ``num_unknowns`` -- **int**; The number of unknown variables allowed.

        RETURN:
        - **tuple**; A tuple containing a list of variables and a list of constraints.
        """
        border_components = self._get_truncated_xor_differential_components_in_border()
        minimize_vars = []
        for border_component in border_components:
            output_id = border_component
            minimize_vars.extend(
                [bit_id for bit_id in self._variables_list if bit_id.startswith(output_id) and bit_id.endswith("_0")]
            )
        return self._sequential_counter(minimize_vars, num_unknowns, "dummy_id_unknown")

    def build_xor_differential_linear_model(
            self,
            weight=-1,
            num_unknown_vars=None,
            unknown_window_size_configuration=None,
    ):
        """
        Constructs a model to search for differential-linear trails.
        This model is a combination of the concrete XOR differential model, the bitwise truncated deterministic model,
        and the linear XOR differential model.

        INPUT:
        - ``weight`` -- **integer** (default: `-1`); specifies the maximum probability weight. If set to a non-negative
        integer, it constrains the search to trails with the fixed probability weight.
        - ``number_of_unknown_variables`` -- **int** (default: None); specifies the upper limit on the number of unknown
        variables allowed in the differential trail.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: component_model_types = []
            sage: for component in speck.get_all_components():
            ....:     component_model_type = {
            ....:         "component_id": component.id,
            ....:         "component_object": component,
            ....:         "model_type": "sat_xor_differential_propagation_constraints"
            ....:     }
            ....:     component_model_types.append(component_model_type)
            sage: sat = SatDifferentialLinearModel(speck, component_model_types)
            sage: sat.build_xor_differential_linear_model()
            ...
        """
        self.build_generic_sat_model_from_dictionary(self.dict_of_components)
        constraints = SatXorLinearModel.branch_xor_linear_constraints(self.bit_bindings)
        self._model_constraints.extend(constraints)

        if num_unknown_vars is not None:
            variables, constraints = self._build_unknown_variable_constraints(num_unknown_vars)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self._build_weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if unknown_window_size_configuration is not None:
            variables, constraints = (
                SatSemiDeterministicTruncatedXorDifferentialModel.unknown_window_size_configuration_constraints(
                    unknown_window_size_configuration,
                    variables_list=self._variables_list,
                    cardinality_constraint_method=self._counter)
            )
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        self._get_connecting_constraints()

    @staticmethod
    def fix_variables_value_constraints(
            fixed_variables, regular_components=None, truncated_components=None, linear_components=None):
        """
        Imposes fixed value constraints on variables within differential, truncated, and linear components.

        INPUT:
        - ``fixed_variables`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``regular_components`` -- **list** (default: None); list of regular components.
        - ``truncated_components`` -- **list** (default: None); list of truncated components.
        - ``linear_components`` -- **list** (default: None); list of linear components.

        RETURN:
        - **list**; A list of constraints for the model.
        """
        truncated_vars = []
        regular_vars = []
        linear_vars = []

        for var in fixed_variables:
            component_id = var["component_id"]

            if component_id in [comp["component_id"] for comp in regular_components] and 2 in var['bit_values']:
                raise ValueError("The fixed value in a regular XOR differential component cannot be 2")

            if component_id in [comp["component_id"] for comp in truncated_components]:
                truncated_vars.append(var)
            elif component_id in [comp["component_id"] for comp in linear_components]:
                linear_vars.append(var)
            elif component_id in [comp["component_id"] for comp in regular_components]:
                regular_vars.append(var)
            else:
                regular_vars.append(var)

        regular_constraints = SatModel.fix_variables_value_constraints(regular_vars)
        truncated_constraints = SatBitwiseDeterministicTruncatedXorDifferentialModel.fix_variables_value_constraints(
            truncated_vars)
        linear_constraints = SatXorLinearModel.fix_variables_value_xor_linear_constraints(linear_vars)

        return regular_constraints + truncated_constraints + linear_constraints

    def _parse_solver_output(self, variable2value):
        """
        Parses the solver's output and returns component solutions and total weight. The total weight is the sum of the
        probability weight of the top part (differential part) and the correlation weight of the bottom part (linear part).
        Note that the weight of the middle part is deterministic.

        INPUT:
        - ``variable2value`` -- **dict**; mapping of solver's variables to their values.

        RETURN:
        - **tuple**; a tuple containing the dictionary of component solutions and the total weight.
        """
        components_solutions = self._get_cipher_inputs_components_solutions('', variable2value)
        total_weight_diff = 0
        total_weight_lin = 0

        for component in self._cipher.get_all_components():
            if component.id in [d['component_id'] for d in self.regular_components]:
                hex_value = self._get_component_hex_value(component, '', variable2value)
                weight = self.calculate_component_weight(component, '', variable2value)
                components_solutions[component.id] = set_component_solution(hex_value, weight)
                total_weight_diff += weight

            elif component.id in [d['component_id'] for d in self.truncated_components]:
                value = self._get_component_value_double_ids(component, variable2value)
                components_solutions[component.id] = set_component_solution(value)

            elif component.id in [d['component_id'] for d in self.linear_components]:
                hex_value = self._get_component_hex_value(component, constants.OUTPUT_BIT_ID_SUFFIX, variable2value)
                weight = self.calculate_component_weight(component, constants.OUTPUT_BIT_ID_SUFFIX, variable2value)
                total_weight_lin += weight
                components_solutions[component.id] = set_component_solution(hex_value, weight)
        print("top part weights:", total_weight_diff)
        print("linear part weights:", total_weight_lin)
        return components_solutions, total_weight_diff + 2 * total_weight_lin

    def find_one_differential_linear_trail_with_fixed_weight(
            self,
            weight,
            num_unknown_vars=None,
            fixed_values=[],
            solver_name=solvers.SOLVER_DEFAULT,
            unknown_window_size_configuration=None
    ):
        """
        Finds one XOR differential-linear trail with a fixed weight. The weight must be the sum of the probability weight
        of the top part (differential part) and the correlation weight of the bottom part (linear part).

        INPUT:
        - ``weight`` -- **int**; Maximum probability weight for the regular XOR differential part.
        - ``num_unknown_vars`` -- **int** (default: None); Upper limit on the number of unknown variables allowed.
        - ``fixed_values`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``solver_name`` -- **str** (default: ``solvers.SOLVER_DEFAULT``); The name of the SAT solver to use.

        RETURN:
        - **dict**; Solution returned by the solver, including the trail and additional information.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: from claasp.cipher_modules.models.sat.utils.utils import _generate_component_model_types, \
            ....:     _update_component_model_types_for_truncated_components, _update_component_model_types_for_linear_components
            sage: import itertools
            sage: speck = SpeckBlockCipher(number_of_rounds=6)
            sage: middle_part_components = []
            sage: bottom_part_components = []
            sage: for round_number in range(2, 4):
            ....:     middle_part_components.append(speck.get_components_in_round(round_number))
            sage: for round_number in range(4, 6):
            ....:     bottom_part_components.append(speck.get_components_in_round(round_number))
            sage: middle_part_components = list(itertools.chain(*middle_part_components))
            sage: bottom_part_components = list(itertools.chain(*bottom_part_components))
            sage: middle_part_components = [component.id for component in middle_part_components]
            sage: bottom_part_components = [component.id for component in bottom_part_components]
            sage: plaintext = set_fixed_variables(
            ....:     component_id='plaintext',
            ....:     constraint_type='equal',
            ....:     bit_positions=range(32),
            ....:     bit_values=integer_to_bit_list(0x02110a04, 32, 'big')
            ....: )
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=(0,) * 64
            ....: )
            sage: modadd_2_7 = set_fixed_variables(
            ....:     component_id='modadd_4_7',
            ....:     constraint_type='not_equal',
            ....:     bit_positions=range(4),
            ....:     bit_values=[0] * 4
            ....: )
            sage: ciphertext_difference = set_fixed_variables(
            ....:     component_id='cipher_output_5_12',
            ....:     constraint_type='equal',
            ....:     bit_positions=range(32),
            ....:     bit_values=integer_to_bit_list(0x02000201, 32, 'big')
            ....: )
            sage: component_model_types = _generate_component_model_types(speck)
            sage: _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
            sage: _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)
            sage: sat_heterogeneous_model = SatDifferentialLinearModel(speck, component_model_types)
            sage: trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
            ....:     weight=8, fixed_values=[key, plaintext, modadd_2_7, ciphertext_difference], solver_name="CADICAL_EXT", num_unknown_vars=31
            ....: )
            sage: trail["status"] == 'SATISFIABLE'
            True

        """
        start_time = time.time()

        self.build_xor_differential_linear_model(weight, num_unknown_vars, unknown_window_size_configuration)
        constraints = self.fix_variables_value_constraints(
            fixed_values,
            self.regular_components,
            self.truncated_components,
            self.linear_components
        )
        self.model_constraints.extend(constraints)

        solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
        solution['building_time_seconds'] = time.time() - start_time
        solution['test_name'] = "find_one_regular_truncated_xor_differential_trail"

        return solution

    def find_lowest_weight_xor_differential_linear_trail(
            self, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT
    ):
        """
        Finds the XOR regular truncated differential trail with the lowest weight.

        INPUT:
        - ``fixed_values`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``solver_name`` -- **str** (default: ``solvers.SOLVER_DEFAULT``); The SAT solver to use.

        RETURN:
        - **dict**; Solution with the trail and metadata (weight, time, memory usage).
        """
        current_weight = 0
        start_building_time = time.time()
        self.build_xor_regular_and_deterministic_truncated_differential_model(current_weight)
        constraints = self.fix_variables_value_constraints(
            fixed_values, self.regular_components, self.truncated_components
        )
        self.model_constraints.extend(constraints)
        end_building_time = time.time()
        solution = self.solve("XOR_DIFFERENTIAL_LINEAR_MODEL", solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']
        while solution['total_weight'] is None:
            current_weight += 1
            self.build_xor_regular_and_deterministic_truncated_differential_model(current_weight)
            self.model_constraints.extend(constraints)
            solution = self.solve("XOR_DIFFERENTIAL_LINEAR_MODEL", solver_name=solver_name)
            total_time += solution['solving_time_seconds']
            max_memory = max(max_memory, solution['memory_megabytes'])

        solution['solving_time_seconds'] = total_time
        solution['memory_megabytes'] = max_memory
        solution['test_name'] = "find_lowest_weight_xor_regular_truncated_differential_trail"

        return solution

    @property
    def cipher(self):
        """
        Returns the cipher instance associated with the model.

        RETURN:
        - **object**; The cipher object being used in this model.
        """
        return self._cipher
