
# ****************************************************************************
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


from claasp.components.cipher_output_component import CipherOutput
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_xor_with_n_input_bits import \
    update_dictionary_that_contains_xor_inequalities_between_n_input_bits, \
    output_dictionary_that_contains_xor_inequalities


def update_xor_linear_constraints_for_more_than_one_bit(constraints, intermediate_var, linked_components, x):
    # value of intermediate output is the xor of all previous branches in the fork
    number_of_inputs = len(linked_components)
    update_dictionary_that_contains_xor_inequalities_between_n_input_bits(number_of_inputs)
    dict_inequalities = output_dictionary_that_contains_xor_inequalities()
    inequalities = dict_inequalities[number_of_inputs]
    for ineq in inequalities:
        constraint = 0
        for index, input_ in enumerate(linked_components):
            char = ineq[index]
            if char == "1":
                constraint += 1 - x[input_]
                last_char = ineq[number_of_inputs]
            elif char == "0":
                constraint += x[input_]
                last_char = ineq[number_of_inputs]
        if last_char == "1":
            constraint += 1 - x[intermediate_var]
            constraints.append(constraint >= 1)
        elif last_char == "0":
            constraint += x[intermediate_var]
            constraints.append(constraint >= 1)


class IntermediateOutput(CipherOutput):
    def __init__(self, current_round_number, current_round_number_of_components,
                 input_id_links, input_bit_positions, output_bit_size, output_tag):
        super().__init__(current_round_number, current_round_number_of_components,
                         input_id_links, input_bit_positions, output_bit_size, True, output_tag)
        self._suffixes = ['_i', '_o']

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists declarations and constraints for OUTPUT component (both intermediate and cipher).

        This is for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_models.cp_xor_linear_model import CpXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: speck_without_key_schedule = speck.remove_key_schedule()
            sage: cp = CpXorLinearModel(speck_without_key_schedule)
            sage: intermediate_component = speck.get_component_from_id("intermediate_output_0_6")
            sage: variables, constraints = intermediate_component.cp_xor_linear_mask_propagation_constraints(cp)
            sage: constraints
            ['constraint intermediate_output_0_6_o[0] = intermediate_output_0_6_i[0];',
             'constraint intermediate_output_0_6_o[1] = intermediate_output_0_6_i[1];',
             'constraint intermediate_output_0_6_o[2] = intermediate_output_0_6_i[2];',
             ...
             'constraint intermediate_output_0_6_i[29] = xor_0_4_o[13];',
             'constraint intermediate_output_0_6_i[30] = xor_0_4_o[14];',
             'constraint intermediate_output_0_6_i[31] = xor_0_4_o[15];']
        """
        variables, constraints = super().cp_xor_linear_mask_propagation_constraints(model)
        bit_bindings = model.bit_bindings_for_intermediate_output[self.id]
        for intermediate_var, linked_components in bit_bindings.items():
            # no fork
            if len(linked_components) == 1:
                constraints.append(f'constraint {intermediate_var} = {linked_components[0]};')
            # fork
            else:
                operation = " + ".join(linked_components)
                constraints.append(f'constraint {intermediate_var} = ({operation}) mod 2;')

        return variables, constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        code = []
        intermediate_output_params = [f'bit_vector_select_word({self.input_id_links[i]},  {self.input_bit_positions[i]})'
                  for i in range(len(self.input_id_links))]
        code.append(f'  {self.id} = bit_vector_CONCAT([{",".join(intermediate_output_params)} ])')
        code.append(f'  if "{self.description[0]}" not in intermediateOutputs.keys():')
        code.append(f'      intermediateOutputs["{self.description[0]}"] = []')
        if convert_output_to_bytes:
            code.append(
                f'  intermediateOutputs["{self.description[0]}"]'
                f'.append(np.packbits({self.id}, axis=0).transpose())')
        else:
            code.append(
                f'  intermediateOutputs["{self.description[0]}"]'
                f'.append({self.id}.transpose())')
        return code

    def get_byte_based_vectorized_python_code(self, params):
        return [f'  {self.id} = {params}[0]',
                f'  if "{self.description[0]}" not in intermediateOutputs.keys():',
                f'      intermediateOutputs["{self.description[0]}"] = []',
                f'  intermediateOutputs["{self.description[0]}"].append({self.id}.transpose())']

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for OUTPUT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: speck_without_key_schedule = speck.remove_key_schedule()
            sage: milp = MilpXorLinearModel(speck_without_key_schedule)
            sage: milp.init_model_in_sage_milp_class()
            sage: intermediate_component = speck.get_component_from_id("intermediate_output_0_6")
            sage: variables, constraints = intermediate_component.milp_xor_linear_mask_propagation_constraints(milp)
            ...
            sage: variables
            [('x[intermediate_output_0_6_0_i]', x_0),
             ('x[intermediate_output_0_6_1_i]', x_1),
             ('x[intermediate_output_0_6_2_i]', x_2),
            ...
            ('x[xor_0_4_14_o]', x_110),
            ('x[xor_0_4_15_o]', x_111)]
            sage: constraints[0]
            x_32 == x_0
        """
        binary_variable = model.binary_variable
        variables, constraints = super().milp_xor_linear_mask_propagation_constraints(model)
        bit_bindings = model.bit_bindings_for_intermediate_output[self.id]
        for intermediate_var, linked_components in bit_bindings.items():
            variables.extend([(f"x[{var}]", binary_variable[var]) for var in linked_components])
            # no fork
            if len(linked_components) == 1:
                constraints.append(binary_variable[intermediate_var] == binary_variable[linked_components[0]])
            # fork
            else:
                update_xor_linear_constraints_for_more_than_one_bit(constraints, intermediate_var,
                                                                    linked_components, binary_variable)

        return variables, constraints

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of constraints for OUTPUT component for SAT XOR linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: speck_without_key_schedule = speck.remove_key_schedule()
            sage: sat = SatXorLinearModel(speck_without_key_schedule)
            sage: intermediate_component = speck.get_component_from_id("intermediate_output_0_6")
            sage: variables, constraints = intermediate_component.sat_xor_linear_mask_propagation_constraints(sat)
            sage: constraints
            ['intermediate_output_0_6_0_i -intermediate_output_0_6_0_o',
             'intermediate_output_0_6_0_o -intermediate_output_0_6_0_i',
             'intermediate_output_0_6_1_i -intermediate_output_0_6_1_o',
             ...
             'xor_0_4_14_o -intermediate_output_0_6_30_i',
             'intermediate_output_0_6_31_i -xor_0_4_15_o',
             'xor_0_4_15_o -intermediate_output_0_6_31_i']
        """
        variables, constraints = super().sat_xor_linear_mask_propagation_constraints(model)
        bit_bindings = model.bit_bindings_for_intermediate_output[self.id]
        for intermediate_var, linked_components in bit_bindings.items():
            # no fork
            if len(linked_components) == 1:
                constraints.extend(sat_utils.cnf_equivalent([intermediate_var] + linked_components))
            # fork
            else:
                result_bit_ids = [f'inter_{i}_{intermediate_var}'
                                  for i in range(len(linked_components) - 2)] + [intermediate_var]
                constraints.extend(sat_utils.cnf_xor_seq(result_bit_ids, linked_components))

        return variables, constraints

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of constraints for OUTPUT component for SMT XOR linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: speck_without_key_schedule = speck.remove_key_schedule()
            sage: smt = SmtXorLinearModel(speck_without_key_schedule)
            sage: intermediate_component = speck.get_component_from_id("intermediate_output_0_6")
            sage: variables, constraints = intermediate_component.smt_xor_linear_mask_propagation_constraints(smt)
            sage: constraints
            ['(assert (= intermediate_output_0_6_0_i intermediate_output_0_6_0_o))',
             '(assert (= intermediate_output_0_6_1_i intermediate_output_0_6_1_o))',
             '(assert (= intermediate_output_0_6_2_i intermediate_output_0_6_2_o))',
             ...
             '(assert (= intermediate_output_0_6_29_i xor_0_4_13_o))',
             '(assert (= intermediate_output_0_6_30_i xor_0_4_14_o))',
             '(assert (= intermediate_output_0_6_31_i xor_0_4_15_o))']
        """
        variables, constraints = super().smt_xor_linear_mask_propagation_constraints(model)
        bit_bindings = model.bit_bindings_for_intermediate_output[self.id]
        for intermediate_var, linked_components in bit_bindings.items():
            # no fork
            if len(linked_components) == 1:
                equation = smt_utils.smt_equivalent([intermediate_var] + linked_components)
                constraints.append(smt_utils.smt_assert(equation))
            # fork
            else:
                operation = smt_utils.smt_xor(linked_components)
                equation = smt_utils.smt_equivalent((intermediate_var, operation))
                constraints.append(smt_utils.smt_assert(equation))

        return variables, constraints
