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


from claasp.cipher_modules.models.sat.utils import constants
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.component import Component
from claasp.input import Input
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT


class CipherOutput(Component):
    """
    Construct a cipher output component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``is_intermediate`` -- **boolean** (default: ``False``); marks the output as intermediate when ``True``.
    - ``output_tag`` -- **string**; output label/tag stored in the component description.

    EXAMPLES::

        sage: from claasp.components.cipher_output_component import CipherOutput
        sage: component = CipherOutput(0, 0, ['input'], [[0, 1, 2, 3]], 4)
        sage: print(component.id)
        cipher_output_0_0
        sage: print(component.type)
        cipher_output
        sage: print(component.description)
        ['cipher_output']
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        is_intermediate=False,
        output_tag="",
    ):
        if is_intermediate:
            component_type = INTERMEDIATE_OUTPUT
            description = [output_tag]
        else:
            component_type = CIPHER_OUTPUT
            description = [CIPHER_OUTPUT]
        component_id = f"{component_type}_{current_round_number}_{current_round_number_of_components}"
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)
        self._suffixes = ["_o"]

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for OUTPUT in CMS CIPHER model.

        This method support OUTPUT operation using more than two operands.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: cipher_output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: cipher_output_component.cms_constraints()
            (['cipher_output_0_0_0', 'cipher_output_0_0_1', 'cipher_output_0_0_2', 'cipher_output_0_0_3'], ['cipher_output_0_0_0 -xor_0_0_0', 'xor_0_0_0 -cipher_output_0_0_0', 'cipher_output_0_0_1 -xor_0_0_1', 'xor_0_0_1 -cipher_output_0_0_1', 'cipher_output_0_0_2 -xor_0_1_0', 'xor_0_1_0 -cipher_output_0_0_2', 'cipher_output_0_0_3 -xor_0_1_1', 'xor_0_1_1 -cipher_output_0_0_3'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.cms_constraints()

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for OUTPUT component.

        (both intermediate and cipher)

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.cp_constraints()
            ([], ['constraint cipher_output_0_0[0] = xor_0_0[0];', 'constraint cipher_output_0_0[1] = xor_0_0[1];', 'constraint cipher_output_0_0[2] = xor_0_1[0];', 'constraint cipher_output_0_0[3] = xor_0_1[1];'])
        """
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_constraints = [f"constraint {self.id}[{i}] = {all_inputs[i]};" for i in range(self.output_bit_size)]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.cp_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists declarations and constraints for OUTPUT component (both
        intermediate and cipher), for CP wordwise deterministic truncated xor
        differential.

        This is for the first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: DummyModel = type('DummyModel', (), {'word_size': 2})
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4, True, 'round_output')
            sage: output_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())
            ([], ['constraint intermediate_output_0_0_value[0] = xor_0_0_value[0];', 'constraint intermediate_output_0_0_value[1] = xor_0_1_value[0];', 'constraint intermediate_output_0_0_active[0] = xor_0_0_active[0];', 'constraint intermediate_output_0_0_active[1] = xor_0_1_active[0];'])
        """
        cp_declarations = []
        all_inputs_active = []
        all_inputs_value = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_active.extend(
                [
                    f"{id_link}_active[{bit_positions[j * model.word_size] // model.word_size}]"
                    for j in range(len(bit_positions) // model.word_size)
                ]
            )
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_value.extend(
                [
                    f"{id_link}_value[{bit_positions[j * model.word_size] // model.word_size}]"
                    for j in range(len(bit_positions) // model.word_size)
                ]
            )
        cp_constraints = [f"constraint {self.id}_value[{i}] = {input_};" for i, input_ in enumerate(all_inputs_value)]
        cp_constraints.extend(
            [f"constraint {self.id}_active[{i}] = {input_};" for i, input_ in enumerate(all_inputs_active)]
        )

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        """
        Return lists declarations and constraints for OUTPUT component (both
        intermediate and cipher), for CP xor differential first step.

        This is for the first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: DummyModel = type('DummyModel', (), {'word_size': 2})
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4, True, 'round_output')
            sage: output_component.cp_xor_differential_propagation_first_step_constraints(DummyModel())
            (['array[0..1] of var 0..1: intermediate_output_0_0;'], ['constraint intermediate_output_0_0[0] = xor_0_0[0];', 'constraint intermediate_output_0_0[1] = xor_0_1[0];'])
        """
        cp_declarations = [f"array[0..{(self.output_bit_size - 1) // model.word_size}] of var 0..1: {self.id};"]
        all_inputs = []
        cp_constraints = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend(
                [
                    f"{id_link}[{bit_positions[j * model.word_size] // model.word_size}]"
                    for j in range(len(bit_positions) // model.word_size)
                ]
            )
        cp_constraints.extend([f"constraint {self.id}[{i}] = {input_};" for i, input_ in enumerate(all_inputs)])

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model):
        return self.cp_constraints()

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists declarations and constraints for OUTPUT component (both
        intermediate and cipher), for CP xor linear.

        This is for xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..3] of var 0..1: cipher_output_0_0_i;', 'array[0..3] of var 0..1: cipher_output_0_0_o;'], ['constraint cipher_output_0_0_o[0] = cipher_output_0_0_i[0];', 'constraint cipher_output_0_0_o[1] = cipher_output_0_0_i[1];', 'constraint cipher_output_0_0_o[2] = cipher_output_0_0_i[2];', 'constraint cipher_output_0_0_o[3] = cipher_output_0_0_i[3];'])
        """
        cp_declarations = [
            f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id}_i;",
            f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id}_o;",
        ]
        cp_constraints = [f"constraint {self.id}_o[{i}] = {self.id}_i[{i}];" for i in range(self.output_bit_size)]

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        code = []
        cipher_output_params = [
            f"bit_vector_select_word({link}, {positions})"
            for link, positions in zip(self.input_id_links, self.input_bit_positions)
        ]
        code.append(f"  {self.id} = bit_vector_CONCAT([{','.join(cipher_output_params)} ])")
        code.append(f'  if "{self.description[0]}" not in intermediateOutputs.keys():')
        code.append(f'      intermediateOutputs["{self.description[0]}"] = []')
        if convert_output_to_bytes:
            code.append(
                f'  intermediateOutputs["{self.description[0]}"].append(np.packbits({self.id}, axis=0).transpose())'
            )
        else:
            code.append(f'  intermediateOutputs["{self.description[0]}"].append({self.id}.transpose())')
        return code

    def cp_continuous_differential_propagation_constraints(self, model):
        component_id = self.id
        ninputs = self.input_bit_size
        num_links = len(self.input_id_links)
        
        cp_declarations = []
        cp_constraints = []
        
        for i in range(num_links):
            link_size = len(self.input_bit_positions[i])
            cp_declarations.append(
                f"array[0..{link_size - 1}] of var -1.0..1.0: x{i+1}_{component_id};"
            )
        
        cp_declarations.append(
            f"array[0..{ninputs - 1}] of var -1.0..1.0: {component_id};"
        )
        
        output_idx = 0
        for i in range(num_links):
            link_size = len(self.input_bit_positions[i])
            for j in range(link_size):
                cp_constraints.append(
                    f"constraint {component_id}[{output_idx}] = x{i+1}_{component_id}[{j}];"
                )
                output_idx += 1
        
        return cp_declarations, cp_constraints

    def get_byte_based_vectorized_python_code(self, params):
        return [
            f"  {self.id} = {params}[0]",
            f'  if "{self.description[0]}" not in intermediateOutputs.keys():',
            f'      intermediateOutputs["{self.description[0]}"] = []',
            "  if integers_inputs_and_outputs:",
            #                f'    intermediateOutputs["{self.description[0]}"].append(evaluate_vectorized_outputs_to_integers([{self.id}.transpose()], {self.input_bit_size}))',
            f'    intermediateOutputs["{self.description[0]}"] = evaluate_vectorized_outputs_to_integers([{self.id}.transpose()], {self.input_bit_size})',
            "  else:",
            f'    intermediateOutputs["{self.description[0]}"].append({self.id}.transpose())',
        ]

    def milp_constraints(self, model):
        """
        Return lists variables and constrains modeling a component of type
        OUTPUT (both intermediate and cipher), for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=4):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=HASH_FUNCTION,
            ....:             cipher_inputs=[INPUT_PLAINTEXT],
            ....:             cipher_inputs_bit_size=[block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         self.add_cipher_output_component([INPUT_PLAINTEXT], [list(range(block_bit_size))], block_bit_size)
            sage: dummy = DummyCipher(block_bit_size=4)
            sage: milp = MilpModel(dummy)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = dummy.component_from_id("cipher_output_0_0")
            sage: variables, constraints = output_component.milp_constraints(milp)
            sage: len(variables)
            8
            sage: str(variables[0]).startswith("('x[plaintext_0]'")
            True
            sage: str(constraints[0]).endswith("== x_0")
            True
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        model.intermediate_output_names.append([self.id, self.output_bit_size])
        for i in range(self.output_bit_size):
            constraints.append(x[output_vars[i]] == x[input_vars[i]])

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints modeling a component of type
        Intermediate_output or Cipher_output for the bitwise deterministic truncated xor differential model.

        EXAMPLE::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=4):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=HASH_FUNCTION,
            ....:             cipher_inputs=[INPUT_PLAINTEXT],
            ....:             cipher_inputs_bit_size=[block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         self.add_cipher_output_component([INPUT_PLAINTEXT], [list(range(block_bit_size))], block_bit_size)
            sage: dummy = DummyCipher(block_bit_size=4)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(dummy)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = dummy.component_from_id("cipher_output_0_0")
            sage: variables, constraints = output_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: len(variables)
            8
            sage: str(variables[0]).startswith("('x_class[plaintext_0]'")
            True
            sage: len(constraints)
            4


        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        model.intermediate_output_names.append([self.id, self.output_bit_size])
        for i in range(self.output_bit_size):
            constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type
        Intermediate_output or Cipher_output for the wordwise deterministic truncated xor differential model.

        EXAMPLE::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=8):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=HASH_FUNCTION,
            ....:             cipher_inputs=[INPUT_PLAINTEXT],
            ....:             cipher_inputs_bit_size=[block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         self.add_cipher_output_component([INPUT_PLAINTEXT], [list(range(block_bit_size))], block_bit_size)
            sage: dummy = DummyCipher(block_bit_size=8)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(dummy)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = dummy.component_from_id("cipher_output_0_0")
            sage: variables, constraints = output_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: len(variables) > 0
            True
            sage: len(constraints) > 0
            True


        """
        x_class = model.trunc_wordvar

        input_vars, output_vars = self._get_wordwise_input_output_linked_class(model)
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_word_size = self.output_bit_size // model.word_size
        model.intermediate_output_names.append([self.id, output_word_size])
        for i in range(output_word_size):
            constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        bit_variables, bit_constraints = self.milp_constraints(model)

        return variables + bit_variables, constraints + bit_constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_wordwise_branch_number_number_of_active_sboxes_constraints(self, model):
        output_ids = self._milp_wordwise_branch_number_active_sboxes_output_ids(model)

        return self._milp_wordwise_branch_number_active_sboxes_pass_through_constraints(
            model, output_ids, "pass-through"
        )

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for OUTPUT component, for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: from claasp.name_mappings import HASH_FUNCTION, INPUT_PLAINTEXT
            sage: class DummyCipher(Cipher):
            ....:     def __init__(self, block_bit_size=4):
            ....:         super().__init__(
            ....:             family_name='dummy_cipher',
            ....:             cipher_type=HASH_FUNCTION,
            ....:             cipher_inputs=[INPUT_PLAINTEXT],
            ....:             cipher_inputs_bit_size=[block_bit_size],
            ....:             cipher_output_bit_size=block_bit_size,
            ....:         )
            ....:         self.add_round()
            ....:         self.add_cipher_output_component([INPUT_PLAINTEXT], [list(range(block_bit_size))], block_bit_size)
            sage: dummy = DummyCipher(block_bit_size=4)
            sage: milp = MilpModel(dummy)
            sage: milp.init_model_in_sage_milp_class()
            sage: output_component = dummy.component_from_id("cipher_output_0_0")
            sage: variables, constraints = output_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: len(variables)
            8
            sage: len(constraints)
            4
        """
        x = model.binary_variable
        constraints = []
        output_bit_size = self.output_bit_size
        model.intermediate_output_names.append([self.id, output_bit_size])
        ind_input_vars, ind_output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in ind_input_vars + ind_output_vars]
        constraints += [x[ind_output_vars[i]] == x[ind_input_vars[i]] for i in range(output_bit_size)]

        return variables, constraints

    def minizinc_constraints(self, model):
        """
        Return variables and constraints for the components with type OUTPUT
        (both intermediate and cipher), for MINIZINC CIPHER constraints.

        INPUT:

        - ``model`` -- **model object**; a model instance
        """

        var_names = self.minizinc_define_var(model.input_postfix, model.output_postfix, model.data_type)
        intermediate_component_string = []
        component_id = self.id
        ninputs = self.input_bit_size
        input_vars = [f"{component_id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{component_id}_{model.output_postfix}{i}" for i in range(ninputs)]

        for input_var, output_var in zip(input_vars, output_vars):
            intermediate_component_string.append(f"constraint {input_var} = {output_var};")

        mzn_input_array = self._create_minizinc_1d_array_from_list(input_vars)
        if self.description[0] in ["round_output", "cipher_output", "round_key_output"]:
            model.mzn_output_directives.append(
                '\noutput ["component description: '
                + self.description[0]
                + ", id: "
                + component_id
                + '_input:" ++ show('
                + mzn_input_array
                + ')++"\\n"];'
                + "\n"
            )

        model.intermediate_constraints_array.append({f"{component_id}_input": input_vars})

        return var_names, intermediate_component_string

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing CIPHER OUTPUT for SAT CIPHER model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.sat_constraints()
            (['cipher_output_0_0_0', 'cipher_output_0_0_1', 'cipher_output_0_0_2', 'cipher_output_0_0_3'], ['cipher_output_0_0_0 -xor_0_0_0', 'xor_0_0_0 -cipher_output_0_0_0', 'cipher_output_0_0_1 -xor_0_0_1', 'xor_0_0_1 -cipher_output_0_0_1', 'cipher_output_0_0_2 -xor_0_1_0', 'xor_0_1_0 -cipher_output_0_0_2', 'cipher_output_0_0_3 -xor_0_1_1', 'xor_0_1_1 -cipher_output_0_0_3'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i]]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing CIPHER OUTPUT for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['cipher_output_0_0_0_0', 'cipher_output_0_0_1_0', 'cipher_output_0_0_2_0', 'cipher_output_0_0_3_0', 'cipher_output_0_0_0_1', 'cipher_output_0_0_1_1', 'cipher_output_0_0_2_1', 'cipher_output_0_0_3_1'], ['cipher_output_0_0_0_0 -xor_0_0_0_0', 'xor_0_0_0_0 -cipher_output_0_0_0_0', 'cipher_output_0_0_1_0 -xor_0_0_1_0', 'xor_0_0_1_0 -cipher_output_0_0_1_0', 'cipher_output_0_0_2_0 -xor_0_1_0_0', 'xor_0_1_0_0 -cipher_output_0_0_2_0', 'cipher_output_0_0_3_0 -xor_0_1_1_0', 'xor_0_1_1_0 -cipher_output_0_0_3_0', 'cipher_output_0_0_0_1 -xor_0_0_0_1', 'xor_0_0_0_1 -cipher_output_0_0_0_1', 'cipher_output_0_0_1_1 -xor_0_0_1_1', 'xor_0_0_1_1 -cipher_output_0_0_1_1', 'cipher_output_0_0_2_1 -xor_0_1_0_1', 'xor_0_1_0_1 -cipher_output_0_0_2_1', 'cipher_output_0_0_3_1 -xor_0_1_1_1', 'xor_0_1_1_1 -cipher_output_0_0_3_1'])
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        constraints = []
        for out_id, in_id in zip(out_ids_0, in_ids_0):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))
        for out_id, in_id in zip(out_ids_1, in_ids_1):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))

        return out_ids_0 + out_ids_1, constraints

    def sat_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing CIPHER OUTPUT for SAT XOR DIFFERENTIAL model

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.sat_xor_differential_propagation_constraints()
            (['cipher_output_0_0_0', 'cipher_output_0_0_1', 'cipher_output_0_0_2', 'cipher_output_0_0_3'], ['cipher_output_0_0_0 -xor_0_0_0', 'xor_0_0_0 -cipher_output_0_0_0', 'cipher_output_0_0_1 -xor_0_0_1', 'xor_0_0_1 -cipher_output_0_0_1', 'cipher_output_0_0_2 -xor_0_1_0', 'xor_0_1_0 -cipher_output_0_0_2', 'cipher_output_0_0_3 -xor_0_1_1', 'xor_0_1_1 -cipher_output_0_0_3'])
        """
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing CIPHER OUTPUT for SAT XOR LINEAR model

        .. SEEALSO::

            :ref:`sat-standard` for the format

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.sat_xor_linear_mask_propagation_constraints()
            (['cipher_output_0_0_0_i', 'cipher_output_0_0_1_i', 'cipher_output_0_0_2_i', 'cipher_output_0_0_3_i', 'cipher_output_0_0_0_o', 'cipher_output_0_0_1_o', 'cipher_output_0_0_2_o', 'cipher_output_0_0_3_o'], ['cipher_output_0_0_0_i -cipher_output_0_0_0_o', 'cipher_output_0_0_0_o -cipher_output_0_0_0_i', 'cipher_output_0_0_1_i -cipher_output_0_0_1_o', 'cipher_output_0_0_1_o -cipher_output_0_0_1_i', 'cipher_output_0_0_2_i -cipher_output_0_0_2_o', 'cipher_output_0_0_2_o -cipher_output_0_0_2_i', 'cipher_output_0_0_3_i -cipher_output_0_0_3_o', 'cipher_output_0_0_3_o -cipher_output_0_0_3_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = []
        for input_bit_id, output_bit_id in zip(input_bit_ids, output_bit_ids):
            constraints.extend(sat_utils.cnf_equivalent([input_bit_id, output_bit_id]))
        result = input_bit_ids + output_bit_ids, constraints
        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing CIPHER OUTPUT for SMT CIPHER model

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.smt_constraints()
                        (['cipher_output_0_0_0', 'cipher_output_0_0_1', 'cipher_output_0_0_2', 'cipher_output_0_0_3'], ['(assert (= cipher_output_0_0_0 xor_0_0_0))', '(assert (= cipher_output_0_0_1 xor_0_0_1))', '(assert (= cipher_output_0_0_2 xor_0_1_0))', '(assert (= cipher_output_0_0_3 xor_0_1_1))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids[i]])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing CIPHER OUTPUT for SMT XOR DIFFERENTIAL model

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.smt_xor_differential_propagation_constraints()
            (['cipher_output_0_0_0', 'cipher_output_0_0_1', 'cipher_output_0_0_2', 'cipher_output_0_0_3'], ['(assert (= cipher_output_0_0_0 xor_0_0_0))', '(assert (= cipher_output_0_0_1 xor_0_0_1))', '(assert (= cipher_output_0_0_2 xor_0_1_0))', '(assert (= cipher_output_0_0_3 xor_0_1_1))'])
        """
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing CIPHER OUTPUT for SMT XOR LINEAR model

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.cipher_output_component import CipherOutput
            sage: output_component = CipherOutput(0, 0, ['xor_0_0', 'xor_0_1'], [[0, 1], [0, 1]], 4)
            sage: output_component.smt_xor_linear_mask_propagation_constraints()
            (['cipher_output_0_0_0_o', 'cipher_output_0_0_1_o', 'cipher_output_0_0_2_o', 'cipher_output_0_0_3_o', 'cipher_output_0_0_0_i', 'cipher_output_0_0_1_i', 'cipher_output_0_0_2_i', 'cipher_output_0_0_3_i'], ['(assert (= cipher_output_0_0_0_i cipher_output_0_0_0_o))', '(assert (= cipher_output_0_0_1_i cipher_output_0_0_1_o))', '(assert (= cipher_output_0_0_2_i cipher_output_0_0_2_o))', '(assert (= cipher_output_0_0_3_i cipher_output_0_0_3_o))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        constraints = []
        for ids in zip(input_bit_ids, output_bit_ids):
            equation = smt_utils.smt_equivalent(ids)
            constraints.append(smt_utils.smt_assert(equation))
        result = output_bit_ids + input_bit_ids, constraints
        return result
