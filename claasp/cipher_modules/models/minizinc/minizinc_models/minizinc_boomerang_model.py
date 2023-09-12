
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

from claasp.cipher_modules.graph_generator import split_cipher_graph_into_top_bottom
from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import \
    MinizincXorDifferentialModel
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, WORD_OPERATION


class MinizincBoomerangModel(MinizincModel):
    def __init__(self, cipher, top_end_ids, bottom_start_ids, middle_ids, window_size_list=None, sat_or_milp='sat'):
        self.top_end_ids = top_end_ids
        self.bottom_start_ids = bottom_start_ids
        self.middle_ids = middle_ids
        self.original_cipher = cipher
        self.top_cipher = None
        self.bottom_cipher = None
        self.intermediate_cipher_outputs = []
        super().__init__(cipher, window_size_list, None, sat_or_milp)
        self.top_graph, self.bottom_graph = split_cipher_graph_into_top_bottom(cipher, self.top_end_ids, self.bottom_start_ids)

    def create_top_and_bottom_ciphers_from_subgraphs(self):
        def removing_empty_rounds(cipher_to_be_checked):
            # removing empty rounds
            for round_number in range(cipher_to_be_checked.number_of_rounds - 1, -1, -1):
                round_object = cipher_to_be_checked.rounds.round_at(round_number)
                list_of_components = round_object.components
                if not list_of_components:
                    del cipher_to_be_checked._rounds._rounds[round_number]

        def removing_nodes_that_are_not_in_list(new_cipher, original_cipher, graph):
            for round_number in range(new_cipher.number_of_rounds):
                round_object = original_cipher.rounds.round_at(round_number)
                list_of_components = round_object.components
                for round_component in list_of_components:
                    if round_component.id not in graph.nodes:
                        component_to_be_removed = new_cipher.get_component_from_id(round_component.id)
                        component_to_be_removed_round = new_cipher.get_round_from_component_id(round_component.id)
                        new_cipher.remove_round_component(component_to_be_removed_round, component_to_be_removed)
                    """
                    if round_component.id.startswith('cipher_output'):
                        if round_component.id in self.intermediate_cipher_outputs:
                            component_to_be_removed = new_cipher.get_component_from_id(round_component.id)
                            component_to_be_removed_round = new_cipher.get_round_from_component_id(round_component.id)
                            new_cipher.remove_round_component(component_to_be_removed_round, component_to_be_removed)
                        else:
                            self.intermediate_cipher_outputs.append(round_component.id)
                    """


        def create_bottom_cipher(original_cipher):
            initial_nodes_from_bottom_graph = [node for node in self.bottom_graph if self.bottom_graph.has_edge(node, node)]
            bottom_cipher = deepcopy(original_cipher)
            new_input_bit_positions = {}
            bottom_cipher._inputs_bit_size = []
            bottom_cipher._inputs = []
            for node_id in initial_nodes_from_bottom_graph:
                old_component = original_cipher.get_component_from_id(node_id)
                new_input_id_links = deepcopy(old_component.input_id_links)
                for input_id_link_e0 in self.top_end_ids:
                    if input_id_link_e0 in old_component.input_id_links:
                        index_e0_end = old_component.input_id_links.index(input_id_link_e0)
                        new_input_id_links[index_e0_end] = "new_" + input_id_link_e0
                        bottom_cipher._inputs.append("new_" + input_id_link_e0)
                        output_bit_size_input_id_link_e0 = original_cipher.get_component_from_id(input_id_link_e0).output_bit_size
                        bottom_cipher._inputs_bit_size.append(output_bit_size_input_id_link_e0)

                bottom_cipher.update_input_id_links_from_component_id(old_component.id, new_input_id_links)
                new_input_bit_positions[old_component.id] = old_component.input_bit_positions

            # check orphans
            for middle_id in self.middle_ids:
                bottom_cipher._inputs.append(middle_id)
                bottom_cipher._inputs_bit_size.append(original_cipher.get_component_from_id(middle_id).output_bit_size)


            removing_nodes_that_are_not_in_list(bottom_cipher, original_cipher, self.bottom_graph)
            removing_empty_rounds(bottom_cipher)

            # resetting rounds
            for round_number in range(bottom_cipher.number_of_rounds):
                bottom_cipher.rounds.round_at(round_number)._id = round_number
            return bottom_cipher

        def create_top_cipher(original_cipher):
            top_cipher = deepcopy(original_cipher)
            removing_nodes_that_are_not_in_list(top_cipher, original_cipher, self.top_graph)
            # remove empty rounds
            removing_empty_rounds(top_cipher)
            return top_cipher

        self.top_cipher = create_top_cipher(self.original_cipher)
        self.bottom_cipher = create_bottom_cipher(self.original_cipher)

    def objective_generator(self, mzn_top_cipher, mzn_bottom_cipher):
        objective_string = []
        modular_addition_concatenation = "++".join(mzn_top_cipher.probability_vars) + "++" +"++".join(mzn_bottom_cipher.probability_vars)
        objective_string.append(f'solve:: int_search({modular_addition_concatenation},'
                                f' smallest, indomain_min, complete)')
        objective_string.append(f'minimize sum({modular_addition_concatenation});')
        mzn_top_cipher.mzn_output_directives.append(f'output ["Total_Probability: "++show(sum('
                                          f'{modular_addition_concatenation}))];')

        return objective_string

    def create_boomerang_model(self, fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher, bcts):
        def create_bct_mzn_constraint_from_component_ids(dLL_id, dRR_id, nLL_id, nRR_id, branch_size):
            dLL_vars = []
            dRR_vars = []
            nLL_vars = []
            nRR_vars = []
            for i in range(branch_size):
                dLL_vars.append(f'{dLL_id}_y{i}')
                dRR_vars.append(f'{dRR_id}_y{i}')
                nLL_vars.append(f'{nLL_id}_y{i}')
                nRR_vars.append(f'{nRR_id}_y{i}')
            dLL_str = ",".join(dLL_vars)
            dRR_str = ",".join(dRR_vars)
            nLL_str = ",".join(nLL_vars)
            nRR_str = ",".join(nRR_vars)

            dLL = f'array1d(0..{branch_size}-1, [{dLL_str}])'
            dRR = f'array1d(0..{branch_size}-1, [{dRR_str}])'
            nLL = f'array1d(0..{branch_size}-1, [{nLL_str}])'
            nRR = f'array1d(0..{branch_size}-1, [{nRR_str}])'

            return f'constraint onlyLargeSwitch_BCT_enum({dLL}, {dRR}, {nLL}, {nRR}, 1, {branch_size}) = true;\n'

        differential_model_top_cipher = MinizincXorDifferentialModel(self.top_cipher, window_size_list=[0 for i in range(self.original_cipher.number_of_rounds)])
        differential_model_top_cipher.build_xor_differential_trail_model(
            -1, fixed_variables_for_top_cipher
        )

        differential_model_bottom_cipher = MinizincXorDifferentialModel(self.bottom_cipher, window_size_list=[0 for i in range(self.original_cipher.number_of_rounds)])
        differential_model_bottom_cipher.build_xor_differential_trail_model(
            -1, fixed_variables_for_bottom_cipher
        )
        #branch_size = 32
        #bct_constraints1 = create_bct_mzn_constraint_from_component_ids('modadd_3_0', 'rot_3_11', 'modadd_4_0',
        #                                                                'new_rot_3_11', branch_size)
        #bct_constraints2 = create_bct_mzn_constraint_from_component_ids('modadd_3_6', 'rot_3_17', 'modadd_4_6',
        #                                                                'new_rot_3_17', branch_size)
        #bct_constraints3 = create_bct_mzn_constraint_from_component_ids('modadd_3_12', 'rot_3_5', 'modadd_4_12',
        #                                                                'new_rot_3_5', branch_size)
        #bct_constraints4 = create_bct_mzn_constraint_from_component_ids('modadd_3_18', 'rot_3_23', 'modadd_4_18',
        #                                                                'new_rot_3_23', branch_size)
        for bct in bcts:
            bct_mzn_model = create_bct_mzn_constraint_from_component_ids(*bct)
            differential_model_bottom_cipher.add_constraint_from_str(bct_mzn_model)
        #differential_model_bottom_cipher.add_constraint_from_str(bct_constraints1)
        #differential_model_bottom_cipher.add_constraint_from_str(bct_constraints2)
        #differential_model_bottom_cipher.add_constraint_from_str(bct_constraints3)
        #differential_model_bottom_cipher.add_constraint_from_str(bct_constraints4)
        differential_model_bottom_cipher.add_constraint_from_str("include \"bct_model.mzn\";\n")

        differential_model_bottom_cipher._model_constraints.extend(self.objective_generator(differential_model_top_cipher, differential_model_bottom_cipher))
        differential_model_bottom_cipher._model_constraints.extend(
            differential_model_bottom_cipher.weight_constraints(max_weight=None, weight=None, operator=">="))

        differential_model_top_cipher._model_constraints.extend(
            differential_model_top_cipher.weight_constraints(max_weight=None, weight=None, operator=">="))

        model_string_top = "\n".join(differential_model_top_cipher.mzn_comments) + "\n".join(differential_model_top_cipher._variables_list) + \
                       "\n".join(differential_model_top_cipher._model_constraints) + "\n".join(differential_model_top_cipher.mzn_output_directives)

        model_string_bottom = "\n".join(differential_model_bottom_cipher.mzn_comments) + "\n".join(differential_model_bottom_cipher._variables_list) + \
                           "\n".join(differential_model_bottom_cipher._model_constraints) + "\n".join(differential_model_bottom_cipher.mzn_output_directives)
        file_path = "."
        prefix = "ws0_"
        if prefix == "":
            filename = f'{file_path}/{differential_model_top_cipher.cipher_id}_mzn_{differential_model_top_cipher.sat_or_milp}.mzn'
        else:
            filename = f'{file_path}/{prefix}_{differential_model_top_cipher.cipher_id}_mzn_{differential_model_top_cipher.sat_or_milp}.mzn'

        f = open(filename, "w")
        f.write(model_string_top+"\n"+model_string_bottom)
        f.close()


