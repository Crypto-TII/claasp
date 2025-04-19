import time
from copy import deepcopy

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import set_component_solution


def add_prefix_id_to_components(cipher, prefix):
    all_components = cipher.rounds.get_all_components()
    for component in all_components:
        component.set_id(f'{prefix}_{component.id}')
        new_input_id_links = [
            f'{prefix}_{input_id_link}' if input_id_link not in cipher.inputs else input_id_link
            for input_id_link in component.input_id_links
        ]

        component.set_input_id_links(new_input_id_links)

    return 0


class SatPnbHighOrderXorDifferentialModel(SatModel):
    def __init__(self, cipher):
        cipher1 = cipher
        cipher2 = deepcopy(cipher)
        add_prefix_id_to_components(cipher1, 'cipher1')
        for round_number in range(cipher.number_of_rounds):
            round_components2 = cipher2.get_components_in_round(round_number)
            cipher1._rounds.rounds[round_number]._components.extend(round_components2)
        self.differential_model = SatXorDifferentialModel(cipher1)
        self.duplicate_round_cipher = cipher1
        super().__init__(cipher)

    def build_pnb_high_order_xor_differential_model(self, weight=-1, fixed_variables=[]):
        self.differential_model.build_xor_differential_trail_model(weight, fixed_variables)
        self._model_constraints = self.differential_model._model_constraints
        self._variables_list = self.differential_model._variables_list
        all_components = self.duplicate_round_cipher.rounds.get_all_components()
        new_constraints = []
        for component in all_components:
            for i in range(32):
                new_constraint_cnf = [f'-cipher1_{component.id}_{i} -{component.id}_{i}']
                new_constraints.extend(new_constraint_cnf)
        self._model_constraints.extend(new_constraints)
        self.differential_model._model_constraints.extend(new_constraints)

    def find_one_pnb_high_order_xor_differential_trail_with_fixed_weight(
            self, weight, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT
    ):
        start_time = time.time()
        self.build_pnb_high_order_xor_differential_model(weight, fixed_variables=fixed_values)
        solution = self.differential_model.solve("XOR_PNB_HIGH_ORDER_XOR_DIFFERENTIAL_MODEL", solver_name=solver_name)
        solution['building_time_seconds'] = time.time() - start_time
        solution['test_name'] = "find_one_pnb_high_order_xor_differential_trail"

        return solution

    def _parse_solver_output(self, variable2value):
        out_suffix = ''
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)

        total_weight = 0
        for component in self._cipher.get_all_components():
            hex_value = self._get_component_hex_value(component, out_suffix, variable2value)
            weight = self.calculate_component_weight(component, out_suffix, variable2value)
            component_solution = set_component_solution(hex_value, weight)
            components_solutions[f'{component.id}{out_suffix}'] = component_solution
            total_weight += weight

        return components_solutions, total_weight
