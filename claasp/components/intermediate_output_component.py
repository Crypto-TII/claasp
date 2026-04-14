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


from claasp.components.cipher_output_component import CipherOutput
from claasp.cipher_modules.models.cp.cp_component_build_result import CpComponentBuildResult
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_xor_with_n_input_bits import (
    update_dictionary_that_contains_xor_inequalities_between_n_input_bits,
    output_dictionary_that_contains_xor_inequalities,
)


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
    """
    Construct an intermediate output component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``output_tag`` -- **string**; output label/tag stored in the component description.

    EXAMPLES::

        sage: from claasp.components.intermediate_output_component import IntermediateOutput
        sage: component = IntermediateOutput(0, 0, ['input'], [[0, 1, 2, 3]], 4, 'round_output')
        sage: print(component.id)
        intermediate_output_0_0
        sage: print(component.type)
        intermediate_output
        sage: print(component.description)
        ['round_output']
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        output_tag,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            True,
            output_tag,
        )
        self._suffixes = ["_i", "_o"]

    def cp_xor_linear_mask_propagation_constraints(self, context, state):
        """
        Return lists declarations and constraints for OUTPUT component (both intermediate and cipher).

        This is for CP xor linear model.

        INPUT:

        - ``context`` -- a ``CpBuildContext`` (read-only build configuration)
        - ``state`` -- ``CpBuildState`` (mutable accumulator for build state)

        EXAMPLES::

            sage: from claasp.components.intermediate_output_component import IntermediateOutput
            sage: intermediate_component = IntermediateOutput(0, 0, ['xor_0_0'], [[0, 1, 2, 3]], 4, 'round_output')
            sage: from claasp.cipher_modules.models.cp.cp_build_context import CpBuildContext
            sage: context = CpBuildContext(cipher=None, word_size=1, data_type='0..1', true_value=1, false_value=0, bit_bindings_for_intermediate_output={
            ....:     'intermediate_output_0_0': {
            ....:         'intermediate_output_0_0_0_i': ['xor_0_0_0_o'],
            ....:         'intermediate_output_0_0_1_i': ['xor_0_0_1_o'],
            ....:         'intermediate_output_0_0_2_i': ['xor_0_0_2_o'],
            ....:         'intermediate_output_0_0_3_i': ['xor_0_0_3_o'],
            ....:     }
            ....: })
            sage: result = intermediate_component.cp_xor_linear_mask_propagation_constraints(context, None)
            sage: len(result.declarations)
            2
            sage: len(result.constraints)
            8
            sage: result.constraints[0]
            'constraint intermediate_output_0_0_o[0] = intermediate_output_0_0_i[0];'
        """
        result = super().cp_xor_linear_mask_propagation_constraints(context, state)
        bit_bindings = context.bit_bindings_for_intermediate_output[self.id]
        for intermediate_var, linked_components in bit_bindings.items():
            # no fork
            if len(linked_components) == 1:
                result.constraints.append(f"constraint {intermediate_var} = {linked_components[0]};")
            # fork
            else:
                operation = " + ".join(linked_components)
                result.constraints.append(f"constraint {intermediate_var} = ({operation}) mod 2;")

        return result

    def cp_semi_deterministic_truncated_xor_differential_constraints(self, context, state):
        return self.cp_constraints()

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        code = []
        intermediate_output_params = [
            f"bit_vector_select_word({self.input_id_links[i]},  {self.input_bit_positions[i]})"
            for i in range(len(self.input_id_links))
        ]
        code.append(f"  {self.id} = bit_vector_CONCAT([{','.join(intermediate_output_params)} ])")
        code.append(f'  if "{self.description[0]}" not in intermediateOutputs.keys():')
        code.append(f'      intermediateOutputs["{self.description[0]}"] = []')
        if convert_output_to_bytes:
            code.append(
                f'  intermediateOutputs["{self.description[0]}"].append(np.packbits({self.id}, axis=0).transpose())'
            )
        else:
            code.append(f'  intermediateOutputs["{self.description[0]}"].append({self.id}.transpose())')
        return code

    def get_byte_based_vectorized_python_code(self, params):
        return [
            f"  {self.id} = {params}[0]",
            f'  if "{self.description[0]}" not in intermediateOutputs.keys():',
            f'      intermediateOutputs["{self.description[0]}"] = []',
            "  if integers_inputs_and_outputs:",
            # f'    intermediateOutputs["{self.description[0]}"].append(evaluate_vectorized_outputs_to_integers([{self.id}.transpose()], {self.input_bit_size}))',
            f'    intermediateOutputs["{self.description[0]}"] = evaluate_vectorized_outputs_to_integers([{self.id}.transpose()], {self.input_bit_size})',
            "  else:",
            f'    intermediateOutputs["{self.description[0]}"].append({self.id}.transpose())',
        ]

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for OUTPUT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=4):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=BLOCK_CIPHER,
            ....:             cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            ....:             cipher_inputs_bit_size=[block_bit_size, block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         xor_component = self.add_XOR_component(
            ....:             [INPUT_PLAINTEXT, INPUT_KEY],
            ....:             [list(range(block_bit_size)), list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:         )
            ....:         self.add_intermediate_output_component(
            ....:             [xor_component.id],
            ....:             [list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:             'round_output',
            ....:         )
            ....:         self.add_cipher_output_component(
            ....:             [xor_component.id],
            ....:             [list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:         )
            sage: dummy = DummyCipher(block_bit_size=4)
            sage: milp = MilpXorLinearModel(dummy)
            sage: milp.init_model_in_sage_milp_class()
            sage: intermediate_component = dummy.get_component_from_id("intermediate_output_0_1")
            sage: variables, constraints = intermediate_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: len(variables)
            12
            sage: len(constraints)
            8
            sage: str(constraints[0]).endswith("== x_0")
            True
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
                update_xor_linear_constraints_for_more_than_one_bit(
                    constraints, intermediate_var, linked_components, binary_variable
                )

        return variables, constraints

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing INTERMEDIATE OUTPUT for SAT XOR LINEAR model

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
            sage: from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=4):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=BLOCK_CIPHER,
            ....:             cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            ....:             cipher_inputs_bit_size=[block_bit_size, block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         xor_component = self.add_XOR_component(
            ....:             [INPUT_PLAINTEXT, INPUT_KEY],
            ....:             [list(range(block_bit_size)), list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:         )
            ....:         self.add_intermediate_output_component(
            ....:             [xor_component.id],
            ....:             [list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:             'round_output',
            ....:         )
            ....:         self.add_cipher_output_component(
            ....:             [xor_component.id],
            ....:             [list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:         )
            sage: dummy = DummyCipher(block_bit_size=4)
            sage: sat = SatXorLinearModel(dummy)
            sage: intermediate_component = dummy.get_component_from_id("intermediate_output_0_1")
            sage: intermediate_component.sat_xor_linear_mask_propagation_constraints(sat)
            (['intermediate_output_0_1_0_i', 'intermediate_output_0_1_1_i', 'intermediate_output_0_1_2_i', 'intermediate_output_0_1_3_i', 'intermediate_output_0_1_0_o', 'intermediate_output_0_1_1_o', 'intermediate_output_0_1_2_o', 'intermediate_output_0_1_3_o'], ['intermediate_output_0_1_0_i -intermediate_output_0_1_0_o', 'intermediate_output_0_1_0_o -intermediate_output_0_1_0_i', 'intermediate_output_0_1_1_i -intermediate_output_0_1_1_o', 'intermediate_output_0_1_1_o -intermediate_output_0_1_1_i', 'intermediate_output_0_1_2_i -intermediate_output_0_1_2_o', 'intermediate_output_0_1_2_o -intermediate_output_0_1_2_i', 'intermediate_output_0_1_3_i -intermediate_output_0_1_3_o', 'intermediate_output_0_1_3_o -intermediate_output_0_1_3_i', 'intermediate_output_0_1_0_i -xor_0_0_0_o', 'xor_0_0_0_o -intermediate_output_0_1_0_i', 'intermediate_output_0_1_1_i -xor_0_0_1_o', 'xor_0_0_1_o -intermediate_output_0_1_1_i', 'intermediate_output_0_1_2_i -xor_0_0_2_o', 'xor_0_0_2_o -intermediate_output_0_1_2_i', 'intermediate_output_0_1_3_i -xor_0_0_3_o', 'xor_0_0_3_o -intermediate_output_0_1_3_i'])
        """
        variables, constraints = super().sat_xor_linear_mask_propagation_constraints(model)
        bit_bindings = model.bit_bindings_for_intermediate_output[self.id]
        for intermediate_var, linked_components in bit_bindings.items():
            # no fork
            if len(linked_components) == 1:
                constraints.extend(sat_utils.cnf_equivalent([intermediate_var] + linked_components))
            # fork
            else:
                result_bit_ids = [f"inter_{i}_{intermediate_var}" for i in range(len(linked_components) - 2)] + [
                    intermediate_var
                ]
                constraints.extend(sat_utils.cnf_xor_seq(result_bit_ids, linked_components))

        return variables, constraints

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing INTERMEDIATE OUTPUT for SMT XOR LINEAR model

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel
            sage: from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=4):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=BLOCK_CIPHER,
            ....:             cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            ....:             cipher_inputs_bit_size=[block_bit_size, block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         xor_component = self.add_XOR_component(
            ....:             [INPUT_PLAINTEXT, INPUT_KEY],
            ....:             [list(range(block_bit_size)), list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:         )
            ....:         self.add_intermediate_output_component(
            ....:             [xor_component.id],
            ....:             [list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:             'round_output',
            ....:         )
            ....:         self.add_cipher_output_component(
            ....:             [xor_component.id],
            ....:             [list(range(block_bit_size))],
            ....:             block_bit_size,
            ....:         )
            sage: dummy = DummyCipher(block_bit_size=4)
            sage: smt = SmtXorLinearModel(dummy)
            sage: intermediate_component = dummy.get_component_from_id("intermediate_output_0_1")
            sage: intermediate_component.smt_xor_linear_mask_propagation_constraints(smt)
            (['intermediate_output_0_1_0_o', 'intermediate_output_0_1_1_o', 'intermediate_output_0_1_2_o', 'intermediate_output_0_1_3_o', 'intermediate_output_0_1_0_i', 'intermediate_output_0_1_1_i', 'intermediate_output_0_1_2_i', 'intermediate_output_0_1_3_i'], ['(assert (= intermediate_output_0_1_0_i intermediate_output_0_1_0_o))', '(assert (= intermediate_output_0_1_1_i intermediate_output_0_1_1_o))', '(assert (= intermediate_output_0_1_2_i intermediate_output_0_1_2_o))', '(assert (= intermediate_output_0_1_3_i intermediate_output_0_1_3_o))', '(assert (= intermediate_output_0_1_0_i xor_0_0_0_o))', '(assert (= intermediate_output_0_1_1_i xor_0_0_1_o))', '(assert (= intermediate_output_0_1_2_i xor_0_0_2_o))', '(assert (= intermediate_output_0_1_3_i xor_0_0_3_o))'])
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
