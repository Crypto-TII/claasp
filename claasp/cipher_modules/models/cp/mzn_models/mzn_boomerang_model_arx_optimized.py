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

from minizinc import Status

from claasp.cipher_modules.models.cp import solvers
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_bct_predicates import get_bct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.utils import group_strings_by_pattern
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import \
    MznXorDifferentialModelARXOptimized


class MznBoomerangModelARXOptimized(MznXorDifferentialModelARXOptimized):
    def __init__(self, cipher, middle_ids, window_size_list=None, sat_or_milp='sat'):
        self.sboxes_ids = middle_ids
        self.original_cipher = cipher
        self.top_cipher = None
        self.bottom_cipher = None
        self.intermediate_cipher_outputs = []
        self.differential_model_top_cipher = None
        self.differential_model_bottom_cipher = None
        self.probability_vars = None
        self.filename = None
        super().__init__(cipher, window_size_list, None, sat_or_milp)

    def build_boomerang_model(self, weight=None, max_weight=None):
        self.dict_of_components = []

        for component in self.original_cipher.get_all_components():
            model_type = (
                "create_bct_mzn_constraint_from_component_ids"
                if component.id in self.sboxes_ids
                else "minizinc_xor_differential_propagation_constraints"
            )
            self.dict_of_components.append({
                "component_id": component.id,
                "component_object": component,
                "model_type": model_type
            })

        self.build_generic_mzn_model_from_dictionary(self.dict_of_components)
        self.extend_model_constraints(
            MznBoomerangModelARXOptimized.objective_generator(self)
        )
        self.extend_model_constraints(
            self.weight_constraints(max_weight=max_weight, weight=weight, operator=">=")
        )

        from claasp.cipher_modules.models.sat.utils.mzn_predicates import get_word_operations

        self._model_constraints.extend([get_word_operations()])
        self._model_constraints.extend([get_bct_operations()])

    @staticmethod
    def objective_generator(mzn_model):
        probability_vars = [
            var for var in mzn_model.probability_vars
            if not any(sbox_id in var for sbox_id in mzn_model.sboxes_ids)
        ]

        objective_string = []
        modular_addition_concatenation = "++".join(probability_vars)
        objective_string.append(f'solve:: int_search({modular_addition_concatenation},'
                                f' smallest, indomain_min, complete)')
        objective_string.append(f'minimize sum({modular_addition_concatenation});')
        mzn_model.mzn_output_directives.append(
            f'output ["Total_Probability: "++show(sum('f'{modular_addition_concatenation}))];'
        )

        return objective_string

    def write_minizinc_model_to_file(self, file_path, prefix=""):
        model_string_top = "\n".join(self.differential_model_top_cipher.mzn_comments) + "\n".join(
            self.differential_model_top_cipher.mzn_output_directives)

        model_string_bottom = "\n".join(self.differential_model_bottom_cipher.mzn_comments) + "\n".join(
            self.differential_model_bottom_cipher.mzn_output_directives)
        if prefix == "":
            filename = f'{file_path}/{self.original_cipher.id}_mzn_{self.differential_model_top_cipher.sat_or_milp}.mzn'
            self.filename = filename
        else:
            filename = f'{file_path}/{prefix}_{self.original_cipher.id}_mzn_'
            filename += f'{self.differential_model_top_cipher.sat_or_milp}.mzn'
            self.filename = filename

        f = open(filename, "w")
        f.write(
            model_string_top + "\n" + model_string_bottom + "\n" + "\n".join(self._variables_list) + "\n" + "\n".join(
                self._model_constraints)
        )
        f.close()

    def parse_components_with_solution(self, result, solution):
        dict_of_component_value = {}

        def get_hex_from_sublists(sublists, bool_dict):
            hex_values = {}
            for sublist in sublists:
                bit_str = ''.join(['1' if bool_dict[val] else '0' for val in sublist])
                component_id = sublist[0][:-3]
                weight = 0
                if component_id.startswith('modadd') and component_id not in self.sboxes_ids:
                    p_modadd_var = [s for s in bool_dict.keys() if s.startswith(f'p_{component_id}')]
                    weight = sum(bool_dict[p_modadd_var[0]])
                hex_values[component_id] = {'value': hex(int(bit_str, 2)), 'weight': weight, 'sign': 1}

            return hex_values

        if result.status not in [Status.UNKNOWN, Status.UNSATISFIABLE, Status.ERROR]:
            list_of_sublist_of_vars = group_strings_by_pattern(self._variables_list)
            dict_of_component_value = get_hex_from_sublists(list_of_sublist_of_vars, solution.__dict__)

        return {'component_values': dict_of_component_value}

    def bct_parse_result(self, result, solver_name, total_weight, model_type):
        parsed_result = {'id': self.cipher_id, 'model_type': model_type, 'solver_name': solver_name}
        if total_weight == "list_of_solutions":
            solutions = []
            for solution in result.solution:
                parsed_solution = {'total_weight': None, 'component_values': {}}
                parsed_solution_non_linear = self.parse_components_with_solution(result, solution)
                solution_total_weight = 0
                for _, item_value_and_weight in parsed_solution.items():
                    solution_total_weight += item_value_and_weight['weight']
                parsed_solution['total_weight'] = solution_total_weight
                parsed_solution = {**parsed_solution_non_linear, **parsed_result}
                solutions.append(parsed_solution)
            return solutions
        else:
            parsed_result['total_weight'] = total_weight
            parsed_result['statistics'] = result.statistics
            parsed_result = {**self.parse_components_with_solution(result, result.solution), **parsed_result}
        parsed_result['statistics']['flatTime'] = parsed_result['statistics']['flatTime'].total_seconds()
        parsed_result['statistics']['time'] = parsed_result['statistics']['time'].total_seconds()

        return parsed_result

    def find_one_boomerang_trail_with_fixed_weight(
            self, weight, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT):
        """
        Finds one XOR differential-linear trail with a fixed weight. The weight must be the sum of the probability weight
        of the top part (differential part) and the correlation weight of the bottom part (linear part).
        """
        start_time = time.time()

        self.build_boomerang_model(weight=weight)
        constraints = self.fix_variables_value_constraints(
            fixed_values
        )

        self.model_constraints.extend(constraints)

        solution = self.solve_for_ARX("Xor")
        import ipdb;
        ipdb.set_trace()
        solution['building_time_seconds'] = time.time() - start_time
        solution['test_name'] = "find_one_boomerang_model"

        return solution
