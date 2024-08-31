import time
from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.name_mappings import INPUT_PLAINTEXT
from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils


class SatRegularAndDeterministicXorTruncatedDifferential(SatModel):
    def __init__(self, cipher, dict_of_components):
        self.dict_of_components = dict_of_components
        self.regular_components = self.get_regular_components()
        self.truncated_components = self.get_truncated_components()
        super().__init__(cipher, "sequential", False)

    def get_regular_components_in_the_border(self):
        regular_components_in_the_border = []
        regular_component_ids = [item['component_id'] for item in self.regular_components]
        for truncated_component in self.truncated_components:
            truncated_component = self.cipher.get_component_from_id(truncated_component['component_id'])
            for input_id_link in truncated_component.input_id_links:
                if input_id_link in regular_component_ids:
                    regular_components_in_the_border.append(input_id_link)
        return regular_components_in_the_border

    def get_connecting_constraints(self):
        regular_components_in_the_border = self.get_regular_components_in_the_border()
        for regular_component_in_the_border in set(regular_components_in_the_border):
            regular_component_in_the_border_claasp = self.cipher.get_component_from_id(regular_component_in_the_border)
            for idx in range(regular_component_in_the_border_claasp.output_bit_size):
                connecting_constraints = sat_utils.get_cnf_bitwise_truncate_constraints(
                    f'{regular_component_in_the_border}_{idx}',
                    f'{regular_component_in_the_border}_{idx}_0',
                    f'{regular_component_in_the_border}_{idx}_1'
                )
                self._model_constraints.extend(connecting_constraints)
                self._variables_list.extend([
                    f'{regular_component_in_the_border}_{idx}',
                    f'{regular_component_in_the_border}_{idx}_0',
                    f'{regular_component_in_the_border}_{idx}_1'
                ])

    def get_regular_components(self):
        regular_components = []
        for component in self.dict_of_components:
            if component['model_type'] == 'sat_xor_differential_propagation_constraints':
                regular_components.append(component)
        return regular_components

    def get_truncated_components(self):
        truncated_components = []
        for component in self.dict_of_components:
            if component['model_type'] == 'sat_bitwise_deterministic_truncated_xor_differential_constraints':
                truncated_components.append(component)
        return truncated_components

    def weight_constraints(self, weight):
        hw_list = [variable_id for variable_id in self._variables_list if variable_id.startswith('hw_')]
        if weight == 0:
            return [], [f'-{variable}' for variable in hw_list]
        return self._counter(hw_list, weight)

    def unknown_variables_constraints(self, number_of_unknown_variables):
        cipher_output_id = self._cipher.get_all_components_ids()[-1]
        set_to_be_minimized = []
        set_to_be_minimized.extend([
            bit_id for bit_id in self._variables_list
            if bit_id.startswith(cipher_output_id) and bit_id.endswith("_0")
        ])
        return self._sequential_counter(set_to_be_minimized, number_of_unknown_variables, "dummy_id_unknown")

    def build_xor_regular_and_deterministic_truncated_differential_model(
            self, weight=-1, number_of_unknown_variables=None, fixed_variables=[]
    ):
        self.build_generic_sat_model_from_dictionary(fixed_variables, self.dict_of_components)
        if number_of_unknown_variables is not None:
            variables, constraints = self.unknown_variables_constraints(number_of_unknown_variables)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
        if weight != -1:
            variables, constraints = self.weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
        self.get_connecting_constraints()

    def _parse_solver_output(self, variable2value):
        out_suffix = ''
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        total_weight = 0
        for component in self._cipher.get_all_components():
            if component.id in [d['component_id'] for d in self.get_regular_components()]:
                hex_value = self._get_component_hex_value(component, out_suffix, variable2value)
                weight = self.calculate_component_weight(component, out_suffix, variable2value)
                component_solution = set_component_solution(hex_value, weight)
                components_solutions[f'{component.id}{out_suffix}'] = component_solution
                total_weight += weight
            if component.id in [d['component_id'] for d in self.get_truncated_components()]:
                value = self._get_component_value_double_ids(component, variable2value)
                component_solution = set_component_solution(value)
                components_solutions[f'{component.id}'] = component_solution
        return components_solutions, total_weight

    def find_one_xor_regular_truncated_differential_trail_with_fixed_weight(
            self, weight, number_of_unknown_vars=None, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT
    ):
        start_building_time = time.time()
        self.build_xor_regular_and_deterministic_truncated_differential_model(
            weight, number_of_unknown_vars, fixed_variables=fixed_values
        )
        end_building_time = time.time()
        solution = self.solve("XOR_REGULAR_DETERMINISTIC_DIFFERENTIAL", solver_name=solver_name)
        solution['building_time_seconds'] = end_building_time - start_building_time
        solution['test_name'] = "find_one_regular_truncated_xor_differential_trail"
        return solution

    def _get_cipher_inputs_components_solutions_double_ids(self, variable2value):
        components_solutions = {}
        for cipher_input, bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            values = []
            for i in range(bit_size):
                value = 0
                if f'{cipher_input}_{i}_0' in variable2value:
                    value ^= variable2value[f'{cipher_input}_{i}_0'] << 1
                if f'{cipher_input}_{i}_1' in variable2value:
                    value ^= variable2value[f'{cipher_input}_{i}_1']
                values.append(f'{value}')
            component_solution = set_component_solution(
                ''.join(values).replace('2', '?').replace('3', '?'))
            components_solutions[cipher_input] = component_solution
        return components_solutions

    @property
    def cipher(self):
        return self._cipher
