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
from copy import deepcopy
from minizinc import Status

from claasp.cipher_modules.graph_generator import split_cipher_graph_into_top_bottom
from claasp.cipher_modules.models.minizinc.utils.mzn_bct_predicates import get_bct_operations
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import \
    MinizincXorDifferentialModel
from claasp.cipher_modules.models.minizinc.utils.utils import group_strings_by_pattern


class MinizincBoomerangModel(MinizincXorDifferentialModel):
    def __init__(self, cipher, top_end_ids, bottom_start_ids, middle_ids, window_size_list=None, sat_or_milp='sat'):
        self.top_end_ids = top_end_ids
        self.bottom_start_ids = bottom_start_ids
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
        self.top_graph, self.bottom_graph = split_cipher_graph_into_top_bottom(cipher, self.top_end_ids,
                                                                               self.bottom_start_ids)

    @staticmethod
    def remove_empty_rounds(cipher):
        for round_number in range(cipher.number_of_rounds - 1, -1, -1):
            if not cipher.rounds.round_at(round_number).components:
                del cipher.rounds.rounds[round_number]

    @staticmethod
    def reduce_cipher(new_cipher, original_cipher, graph):
        for round_number in range(new_cipher.number_of_rounds):
            MinizincBoomerangModel.remove_components_not_in_graph(new_cipher, original_cipher, round_number, graph)

    @staticmethod
    def remove_components_not_in_graph(new_cipher, original_cipher, round_number, graph):
        round_object = original_cipher.rounds.round_at(round_number)
        for component in round_object.components:
            if component.id not in graph.nodes:
                MinizincBoomerangModel.remove_component(new_cipher, component)

    @staticmethod
    def remove_component(new_cipher, component):
        component_to_remove = new_cipher.get_component_from_id(component.id)
        round_number = new_cipher.get_round_from_component_id(component.id)
        new_cipher.remove_round_component(round_number, component_to_remove)

    @staticmethod
    def initialize_bottom_cipher(original_cipher):
        bottom_cipher = deepcopy(original_cipher)
        bottom_cipher._id = f'{original_cipher.id}_bottom'
        return bottom_cipher

    def setup_bottom_cipher_inputs(self, bottom_cipher, original_cipher):
        initial_nodes = [node for node in self.bottom_graph if self.bottom_graph.has_edge(node, node)]
        new_input_bit_positions = {}
        bottom_cipher._inputs_bit_size = []
        bottom_cipher._inputs = []
        self.update_bottom_cipher_inputs(bottom_cipher, original_cipher, initial_nodes, new_input_bit_positions)

        for middle_id in self.sboxes_ids:
            bottom_cipher._inputs.append(middle_id)
            bottom_cipher._inputs_bit_size.append(
                original_cipher.get_component_from_id(middle_id).output_bit_size
            )

    def update_bottom_cipher_inputs(self, bottom_cipher, original_cipher, initial_nodes, new_input_bit_positions):
        for node_id in initial_nodes:
            old_component = original_cipher.get_component_from_id(node_id)
            new_input_id_links = self.get_new_input_id_links(old_component, bottom_cipher)
            bottom_cipher.update_input_id_links_from_component_id(old_component.id, new_input_id_links)
            new_input_bit_positions[old_component.id] = old_component.input_bit_positions

    def get_new_input_id_links(self, component, bottom_cipher):
        new_input_id_links = deepcopy(component.input_id_links)
        for input_id_link in self.top_end_ids:
            if input_id_link in component.input_id_links:
                index = component.input_id_links.index(input_id_link)
                new_input_id_links[index] = "new_" + input_id_link
                bottom_cipher.inputs.append("new_" + input_id_link)
                output_bit_size = component.output_bit_size
                bottom_cipher.inputs_bit_size.append(output_bit_size)
        return new_input_id_links

    def create_top_and_bottom_ciphers_from_subgraphs(self):
        self.top_cipher = self.create_top_cipher(self.original_cipher)
        self.bottom_cipher = self.create_bottom_cipher(self.original_cipher)

    def create_bottom_cipher(self, original_cipher):
        bottom_cipher = MinizincBoomerangModel.initialize_bottom_cipher(original_cipher)
        self.setup_bottom_cipher_inputs(bottom_cipher, original_cipher)
        MinizincBoomerangModel.reduce_cipher(bottom_cipher, original_cipher, self.bottom_graph)
        MinizincBoomerangModel.remove_empty_rounds(bottom_cipher)
        MinizincBoomerangModel.reset_round_ids(bottom_cipher)
        return bottom_cipher

    def create_top_cipher(self, original_cipher):
        top_cipher = deepcopy(original_cipher)
        top_cipher._id = f'{original_cipher.id}_top'
        MinizincBoomerangModel.reduce_cipher(top_cipher, original_cipher, self.top_graph)
        MinizincBoomerangModel.remove_empty_rounds(top_cipher)
        return top_cipher

    @staticmethod
    def reset_round_ids(cipher):
        for round_number in range(cipher.number_of_rounds):
            cipher.rounds.round_at(round_number)._id = round_number

    @staticmethod
    def objective_generator(mzn_top_cipher, mzn_bottom_cipher):
        objective_string = []
        modular_addition_concatenation = "++".join(mzn_top_cipher.probability_vars) + "++" + "++".join(
            mzn_bottom_cipher.probability_vars)
        objective_string.append(f'solve:: int_search({modular_addition_concatenation},'
                                f' smallest, indomain_min, complete)')
        objective_string.append(f'minimize sum({modular_addition_concatenation});')
        mzn_top_cipher.mzn_output_directives.append(f'output ["Total_Probability: "++show(sum('
                                                    f'{modular_addition_concatenation}))];')

        return objective_string

    def create_boomerang_model(self, fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher):
        self.create_top_and_bottom_ciphers_from_subgraphs()

        self.differential_model_top_cipher = MinizincXorDifferentialModel(
            self.top_cipher, window_size_list=[0 for _ in range(self.top_cipher.number_of_rounds)],
            sat_or_milp='sat', include_word_operations_mzn_file=False
        )
        self.differential_model_top_cipher.build_xor_differential_trail_model(
            -1, fixed_variables_for_top_cipher
        )

        self.differential_model_bottom_cipher = MinizincXorDifferentialModel(
            self.bottom_cipher, window_size_list=[0 for _ in range(self.bottom_cipher.number_of_rounds)],
            sat_or_milp='sat', include_word_operations_mzn_file=False
        )
        self.differential_model_bottom_cipher.build_xor_differential_trail_model(
            -1, fixed_variables_for_bottom_cipher
        )

        for sbox_component_id in self.sboxes_ids:
            sbox_component = self.original_cipher.get_component_from_id(sbox_component_id)
            bct_mzn_model = sbox_component.create_bct_mzn_constraint_from_component_ids()
            self.differential_model_bottom_cipher.add_constraint_from_str(bct_mzn_model)

        self.differential_model_bottom_cipher.extend_model_constraints(
            MinizincBoomerangModel.objective_generator(self.differential_model_top_cipher,
                                                       self.differential_model_bottom_cipher)
        )
        self.differential_model_bottom_cipher.extend_model_constraints(
            self.differential_model_bottom_cipher.weight_constraints(max_weight=None, weight=None, operator=">="))

        self.differential_model_top_cipher.extend_model_constraints(
            self.differential_model_top_cipher.weight_constraints(max_weight=None, weight=None, operator=">="))
        from claasp.cipher_modules.models.sat.utils.mzn_predicates import get_word_operations
        self._model_constraints.extend([get_word_operations()])
        self._model_constraints.extend([get_bct_operations()])

        self._variables_list.extend(self.differential_model_top_cipher.get_variables() +
                                    self.differential_model_bottom_cipher.get_variables())
        self._model_constraints.extend(self.differential_model_top_cipher.get_model_constraints() +
                                       self.differential_model_bottom_cipher.get_model_constraints())
        top_cipher_probability_vars = self.differential_model_top_cipher.probability_vars
        bottom_cipher_probability_vars = self.differential_model_bottom_cipher.probability_vars

        self.probability_vars = top_cipher_probability_vars + bottom_cipher_probability_vars

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
