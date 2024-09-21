import time
from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import (
    SatBitwiseDeterministicTruncatedXorDifferentialModel
)
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.cipher_modules.models.sat.utils import utils as sat_utils


class SatProbabilisticXorTruncatedDifferential(SatModel):
    """
    Model that combines regular XOR differential constraints with bitwise deterministic truncated XOR differential constraints.
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
        self.truncated_components = self._get_components_by_type(
            'sat_bitwise_deterministic_truncated_xor_differential_constraints')
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

    def _get_connecting_constraints(self):
        """
        Adds constraints for connecting regular and truncated components.
        """
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

    def _build_weight_constraints(self, weight):
        """
        Builds weight constraints for the model based on the specified weight.

        INPUT:
        - ``weight`` -- **int**; The weight to constrain the search. If set to 0, the hardware variables are negated.

        RETURN:
        - **tuple**; A tuple containing a list of variables and a list of constraints.
        """
        hw_variables = [var_id for var_id in self._variables_list if var_id.startswith('hw_')]

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
        output_id = self._cipher.get_all_components_ids()[-1]
        minimize_vars = [bit_id for bit_id in self._variables_list if
                         bit_id.startswith(output_id) and bit_id.endswith("_0")]
        return self._sequential_counter(minimize_vars, num_unknowns, "dummy_id_unknown")

    def build_xor_probabilistic_truncated_differential_model(self, weight=-1, num_unknown_vars=None):
        """
        Constructs a model to search for probabilistic truncated XOR differential trails.
        This model is a combination of the regular XOR differential model and of the bitwise truncated deterministic model.

        INPUT:
        - ``weight`` -- **integer** (default: `-1`); specifies the maximum probability weight. If set to a non-negative
        integer, it constrains the search to trails with the fixed probability weight.
        - ``number_of_unknown_variables`` -- **int** (default: None); specifies the upper limit on the number of unknown
        variables allowed in the differential trail.
        - ``fixed_variables`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific
        values. Each entry in the list should be a dictionary representing constraints for specific components, written
        in the CLAASP constraining syntax.


        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_probabilistic_xor_truncated_differential_model import SatProbabilisticXorTruncatedDifferential
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
            sage: sat = SatProbabilisticXorTruncatedDifferential(speck, component_model_types)
            sage: sat.build_xor_probabilistic_truncated_differential_model()
            ...
        """
        self.build_generic_sat_model_from_dictionary(self.dict_of_components)

        if num_unknown_vars is not None:
            variables, constraints = self._build_unknown_variable_constraints(num_unknown_vars)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self._build_weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        self._get_connecting_constraints()

    @staticmethod
    def fix_variables_value_constraints(fixed_variables, regular_components=None, truncated_components=None):
        """
        Fixes variable value constraints for regular and truncated components.

        INPUT:
        - ``fixed_variables`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``regular_components`` -- **list** (default: None); list of regular components.
        - ``truncated_components`` -- **list** (default: None); list of truncated components.

        RETURN:
        - **list**; A list of constraints for the model.
        """
        truncated_vars = []
        regular_vars = []

        for var in fixed_variables:
            component_id = var["component_id"]

            if component_id in [comp["component_id"] for comp in regular_components] and 2 in var['bit_values']:
                raise ValueError("The fixed value in a regular XOR differential component cannot be 2")

            if component_id in [comp["component_id"] for comp in truncated_components]:
                truncated_vars.append(var)
            else:
                regular_vars.append(var)

        regular_constraints = SatModel.fix_variables_value_constraints(regular_vars)
        truncated_constraints = SatBitwiseDeterministicTruncatedXorDifferentialModel.fix_variables_value_constraints(
            truncated_vars)

        return regular_constraints + truncated_constraints

    def _parse_solver_output(self, variable2value):
        """
        Parses the solver's output and returns component solutions and total weight.

        INPUT:
        - ``variable2value`` -- **dict**; mapping of solver's variables to their values.

        RETURN:
        - **tuple**; a tuple containing the dictionary of component solutions and the total weight.
        """
        out_suffix = ''
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        total_weight = 0

        for component in self._cipher.get_all_components():
            if component.id in [d['component_id'] for d in self.regular_components]:
                hex_value = self._get_component_hex_value(component, '', variable2value)
                weight = self.calculate_component_weight(component, '', variable2value)
                components_solutions[component.id] = set_component_solution(hex_value, weight)
                total_weight += weight
            elif component.id in [d['component_id'] for d in self.truncated_components]:
                value = self._get_component_value_double_ids(component, variable2value)
                components_solutions[component.id] = set_component_solution(value)

        return components_solutions, total_weight

    def find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight(
            self, weight, num_unknown_vars=None, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Finds one XOR probabilistic truncated differential trail with a fixed weight.

        INPUT:
        - ``weight`` -- **int**; Maximum probability weight for the regular xor differential part.
        - ``num_unknown_vars`` -- **int** (default: None); Upper limit on the number of unknown variables allowed.
        - ``fixed_values`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``solver_name`` -- **str** (default: ``solvers.SOLVER_DEFAULT``); The name of the SAT solver to use.

        RETURN:
        - **dict**; Solution returned by the solver, including the trail and additional metadata.
        """
        start_time = time.time()

        self.build_xor_probabilistic_truncated_differential_model(weight, num_unknown_vars)
        constraints = self.fix_variables_value_constraints(fixed_values, self.regular_components,
                                                           self.truncated_components)
        self.model_constraints.extend(constraints)

        solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
        solution['building_time_seconds'] = time.time() - start_time
        solution['test_name'] = "find_one_regular_truncated_xor_differential_trail"

        return solution

    def find_lowest_weight_xor_probabilistic_truncated_differential_trail(self, fixed_values=[],
                                                                          solver_name=solvers.SOLVER_DEFAULT):
        """
        Finds the XOR probabilistic truncated differential trail with the lowest weight.

        INPUT:
        - ``fixed_values`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``solver_name`` -- **str** (default: ``solvers.SOLVER_DEFAULT``); The SAT solver to use.

        RETURN:
        - **dict**; Solution with the trail and metadata (weight, time, memory usage).
        """
        current_weight = 0
        start_building_time = time.time()
        self.build_xor_probabilistic_truncated_differential_model(current_weight)
        constraints = self.fix_variables_value_constraints(fixed_values, self.regular_components,
                                                           self.truncated_components)
        end_building_time = time.time()
        self.model_constraints.extend(constraints)
        solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']

        while solution['total_weight'] is None:
            current_weight += 1
            start_building_time = time.time()
            self.build_xor_probabilistic_truncated_differential_model(current_weight)
            self.model_constraints.extend(constraints)
            solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
            end_building_time = time.time()

            solution['building_time_seconds'] = end_building_time - start_building_time
            total_time += solution['solving_time_seconds']
            max_memory = max(max_memory, solution['memory_megabytes'])

        solution['solving_time_seconds'] = total_time
        solution['memory_megabytes'] = max_memory
        solution['test_name'] = "find_lowest_weight_xor_probabilistic_truncated_differential_trail"

        return solution

    @property
    def cipher(self):
        """
        Returns the cipher instance associated with the model.

        RETURN:
        - **object**; The cipher object being used in this model.
        """
        return self._cipher
