import time
from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import (
    SatBitwiseDeterministicTruncatedXorDifferentialModel
)
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.cipher_modules.models.utils import set_component_solution, get_bit_bindings
from claasp.cipher_modules.models.sat.utils import utils as sat_utils, constants

# TODO: This class have several methods similar to the SatBitwiseDeterministicTruncatedXorDifferentialModel classes. It is possible to refactor the code to avoid code duplication.
# TODO: Check all docstrings.
class SatDifferentialLinearModel(SatModel):
    """
    Model that combines concrete XOR differential model with bitwise deterministic truncated differential model
    and linear model to create differential-linear model.
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
        Retrieves regular components that are connected to truncated components (border components).

        RETURN:
        - **list**; A list of regular components at the border.
        """
        truncated_component_ids = {item['component_id'] for item in self.truncated_components}
        border_components = []

        for linear_component in self.linear_components:
            component_obj = self.cipher.get_component_from_id(linear_component['component_id'])
            for input_id in component_obj.input_id_links:
                if input_id in truncated_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_connecting_constraints(self):
        def is_any_string_in_list_substring_of_string(string, string_list):
            # Check if any string in the list is a substring of the given string
            return any(s in string for s in string_list)
        """
        Adds constraints for connecting regular and truncated components.
        """
        border_components = self._get_regular_xor_differential_components_in_border()
        #print(border_components)
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

        print(border_components)

        linear_component_ids = [item['component_id'] for item in self.linear_components]

        for component_id in border_components:

            component = self.cipher.get_component_from_id(component_id)
            for idx in range(component.output_bit_size):
                truncated_component = f'{component_id}_{idx}_o'
                component_sucessors = self.bit_bindings[truncated_component]
                for component_sucessor in component_sucessors:
                    length_component_sucessor = len(component_sucessor)
                    component_sucessor_id = component_sucessor[:length_component_sucessor-2]

                    if is_any_string_in_list_substring_of_string(component_sucessor_id, linear_component_ids):
                        #import ipdb;
                        #ipdb.set_trace()
                        constraints = sat_utils.get_cnf_truncated_linear_constraints(
                           component_sucessor, f'{component_id}_{idx}_0'
                        )
                        self._model_constraints.extend(constraints)
                        self._variables_list.extend([component_sucessor, f'{component_id}_{idx}_0'])

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
        border_components = self._get_truncated_xor_differential_components_in_border()
        minimize_vars = []
        for border_component in border_components:
            output_id = border_component
            minimize_vars.extend(
                [bit_id for bit_id in self._variables_list if bit_id.startswith(output_id) and bit_id.endswith("_0")]
            )
        return self._sequential_counter(minimize_vars, num_unknowns, "dummy_id_unknown")

    # TODO: Allow as input parameters probability_weight and correlation_weight
    def build_xor_differential_linear_model(self, weight=-1, num_unknown_vars=None):
        """
        Constructs a model to search for probabilistic truncated XOR differential trails.
        This model is a combination of the concrete XOR differential model,the bitwise truncated deterministic model and
        the linear XOR differential model.

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
        constraints = self.branch_xor_linear_constraints()
        self._model_constraints.extend(constraints)

        if num_unknown_vars is not None:
            variables, constraints = self._build_unknown_variable_constraints(num_unknown_vars)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self._build_weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        ciphertext_output_vars = [f'cipher_output_7_24_{i}_o' for i in range(512)]
#
        variables, constraints = self._sequential_counter_algorithm(ciphertext_output_vars, 5, 'dummy_hw_ac')
        self._variables_list.extend(variables)
        self._model_constraints.extend(constraints)



        self._get_connecting_constraints()

    @staticmethod
    def fix_variables_value_constraints(
            fixed_variables, regular_components=None, truncated_components=None, linear_components=None
    ):
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
        # TODO: temporary I created the method fix_variables_value_xor_linear_constraints1 in the SatXorLinearModel class it is necessary refactor the method fix_variables_value_xor_linear_constraints from the SatXorLinearModel class to a static.
        linear_constraints = SatXorLinearModel.fix_variables_value_xor_linear_constraints1(linear_vars)

        return regular_constraints + truncated_constraints + linear_constraints

    # TODO: Add key-value to discriminate probability and correlation weights
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
        total_weight_diff = 0
        total_weight_lin = 0
        total_weight_lin_input = 0
        for component in self._cipher.get_all_components():
            if component.id in [d['component_id'] for d in self.regular_components]:
                hex_value = self._get_component_hex_value(component, '', variable2value)
                weight = self.calculate_component_weight(component, '', variable2value)
                components_solutions[component.id] = set_component_solution(hex_value, weight)
                total_weight_diff += weight

            elif component.id in [d['component_id'] for d in self.truncated_components]:
                value = self._get_component_value_double_ids(component, variable2value)
                components_solutions[component.id] = set_component_solution(value)

                out_sufix = constants.OUTPUT_BIT_ID_SUFFIX
                hex_value = self._get_component_hex_value(component, out_sufix, variable2value)
                components_solutions[component.id+"_o"] = set_component_solution(hex_value, 0)

            elif component.id in [d['component_id'] for d in self.linear_components]:
                out_sufix = constants.OUTPUT_BIT_ID_SUFFIX
                hex_value = self._get_component_hex_value(component, out_sufix, variable2value)
                weight = self.calculate_component_weight(component, out_sufix, variable2value)
                total_weight_lin += weight
                input_sufix = constants.INPUT_BIT_ID_SUFFIX
                hex_value_input = self._get_component_hex_value_input(component, input_sufix, variable2value)
                #weight_input = self.calculate_component_weight(component, input_sufix, variable2value)
                #total_weight_lin_input += weight_input

                components_solutions[component.id] = set_component_solution(hex_value, weight)
                components_solutions[component.id + "_input"] = set_component_solution(hex_value_input, 0)
                components_solutions[component.id + "_input"]["links"] = str(component.input_id_links)
                components_solutions[component.id + "_input_id_links"] = {}
                for input_id_link in component.input_id_links:
                    components_solutions[component.id + "_input_id_links"][input_id_link] = self._get_component_hex_value(
                        self.cipher.get_component_from_id(input_id_link), out_sufix, variable2value)

                #if component.id == "modadd_4_18":
                #    components_solutions[component.id + "_input"]["modadd_3_18"] = self._get_component_hex_value(self.cipher.get_component_from_id("modadd_3_18"), out_sufix, variable2value)
        print("total_weight_diff, total_weight_lin", total_weight_diff, total_weight_lin)

        return components_solutions, total_weight_diff + 2*total_weight_lin

    def find_one_differential_linear_trail_with_fixed_weight(
            self, weight, num_unknown_vars=None, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Finds one XOR regular truncated differential trail with a fixed weight.

        INPUT:
        - ``weight`` -- **int**; Maximum probability weight for the regular xor differential part.
        - ``num_unknown_vars`` -- **int** (default: None); Upper limit on the number of unknown variables allowed.
        - ``fixed_values`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``solver_name`` -- **str** (default: ``solvers.SOLVER_DEFAULT``); The name of the SAT solver to use.

        RETURN:
        - **dict**; Solution returned by the solver, including the trail and additional metadata.
        """
        start_time = time.time()

        self.build_xor_differential_linear_model(weight, num_unknown_vars)
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

    def find_lowest_weight_xor_regular_truncated_differential_trail(self, fixed_values=[],
                                                                    solver_name=solvers.SOLVER_DEFAULT):
        """
        Finds the XOR regular truncated differential trail with the lowest weight.

        INPUT:
        - ``fixed_values`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``solver_name`` -- **str** (default: ``solvers.SOLVER_DEFAULT``); The SAT solver to use.

        RETURN:
        - **dict**; Solution with the trail and metadata (weight, time, memory usage).
        """
        current_weight = 0
        start_time = time.time()

        self.build_xor_regular_and_deterministic_truncated_differential_model(current_weight)
        constraints = self.fix_variables_value_constraints(fixed_values, self.regular_components,
                                                           self.truncated_components)
        self.model_constraints.extend(constraints)

        solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
        total_time = solution['solving_time_seconds']
        max_memory = solution['memory_megabytes']

        while solution['total_weight'] is None:
            current_weight += 1
            start_building_time = time.time()
            self.build_xor_regular_and_deterministic_truncated_differential_model(current_weight)
            self.model_constraints.extend(constraints)
            solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
            end_building_time = time.time()

            solution['building_time_seconds'] = end_building_time - start_building_time
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

    # TODO: it is possible to use the branch_xor_linear_constraints method from the linear sat model converting it to a static method
    def branch_xor_linear_constraints(self):
        """
        Return lists of variables and clauses for branch in XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatXorLinearModel(speck)
            sage: sat.branch_xor_linear_constraints()
            ['-plaintext_0_o rot_0_0_0_i',
             'plaintext_0_o -rot_0_0_0_i',
             '-plaintext_1_o rot_0_0_1_i',
             ...
             'xor_2_10_14_o -cipher_output_2_12_30_i',
             '-xor_2_10_15_o cipher_output_2_12_31_i',
             'xor_2_10_15_o -cipher_output_2_12_31_i']
        """
        constraints = []
        for output_bit, input_bits in self.bit_bindings.items():
            constraints.extend(sat_utils.cnf_xor(output_bit, input_bits))

        return constraints