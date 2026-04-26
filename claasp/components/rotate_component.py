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


from claasp.input import Input
from claasp.component import Component
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils
from claasp.name_mappings import WORD_OPERATION


class Rotate(Component):
    """
    Construct a rotate component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``parameter`` -- **integer**; operation parameter (for example shift/rotation amount). Negative values are allowed when semantics supports them.

    EXAMPLES::

        sage: from claasp.components.rotate_component import Rotate
        sage: component = Rotate(0, 0, ['input'], [[0, 1]], 2, -1)
        sage: print(component.id)
        rot_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['ROTATE', -1]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        parameter,
    ):
        component_id = f"rot_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        description = ["ROTATE", parameter]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for bitwise ROTATION.

        INPUT:

        - ``model`` --  **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = RotateCipher(bit_size=2, parameter=1)
            sage: rotate_component = cipher.component_from_id('rot_0_0')
            sage: algebraic = AlgebraicModel(cipher)
            sage: rotate_component.algebraic_polynomials(algebraic)
            [rot_0_0_y0 + rot_0_0_x1, rot_0_0_y1 + rot_0_0_x0]
        """
        if self.description[0].lower() != "rotate":
            raise ValueError("component must be bitwise rotation")

        rotation_const = self.description[1]
        ninputs = noutputs = self.output_bit_size
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        ring_R = model.ring()
        x = list(map(ring_R, input_vars))
        y = list(map(ring_R, output_vars))
        polynomials = [y[i] + x[(rotation_const + i) % noutputs] for i in range(noutputs)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for ROTATION in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.cms_constraints()
            (['rot_0_0_0', 'rot_0_0_1'], ['rot_0_0_0 -input_1', 'input_1 -rot_0_0_0', 'rot_0_0_1 -input_0', 'input_0 -rot_0_0_1'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for ROTATE component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.cp_constraints()
            ([], ['constraint rot_0_0[0] = input[1];', 'constraint rot_0_0[1] = input[0];'])
        """
        rot_amount = abs(self.description[1])
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_declarations = []
        input_len = len(all_inputs)
        if rot_amount == self.description[1]:
            cp_constraints = [
                f"constraint {self.id}[{i}] = {all_inputs[(i - rot_amount) % input_len]};"
                for i in range(self.output_bit_size)
            ]
        else:
            cp_constraints = [
                f"constraint {self.id}[{i}] = {all_inputs[(i + rot_amount) % input_len]};"
                for i in range(self.output_bit_size)
            ]

        return cp_declarations, cp_constraints

    def cp_continuous_differential_propagation_constraints(self, model):

        output_id_link = self.id
        input_len = self.output_bit_size
        rot_val = self.description[1]

        cp_declarations = []
        cp_constraints = []

        cp_declarations.append(
            f"array[0..{input_len - 1}] of var -1.0..1.0: x1_{output_id_link};"
        )
        cp_declarations.append(
            f"array[0..{input_len - 1}] of var -1.0..1.0: {output_id_link};"
        )

        if rot_val > 0:
            cp_constraints.append(
                f"constraint {output_id_link} = continuous_RRot(x1_{output_id_link}, {rot_val}, {output_id_link});"
            )
        else:
            cp_constraints.append(
                f"constraint {output_id_link} = continuous_LRot(x1_{output_id_link}, {abs(rot_val)}, {output_id_link});"
            )

        return cp_declarations, cp_constraints
        
    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.cp_constraints()

    def cp_inverse_constraints(self):
        """
        Return lists of declarations and constraints for ROTATE component for CP INVERSE CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.cp_inverse_constraints()
            ([], ['constraint rot_0_0_inverse[0] = input[1];', 'constraint rot_0_0_inverse[1] = input[0];'])
        """
        rot_amount = abs(self.description[1])
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        cp_declarations = []
        input_len = len(all_inputs)
        if rot_amount == self.description[1]:
            cp_constraints = [
                f"constraint {self.id}_inverse[{i}] = {all_inputs[(i - rot_amount) % input_len]};"
                for i in range(self.output_bit_size)
            ]
        else:
            cp_constraints = [
                f"constraint {self.id}_inverse[{i}] = {all_inputs[(i + rot_amount) % input_len]};"
                for i in range(self.output_bit_size)
            ]

        return cp_declarations, cp_constraints

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        cp_declarations = []
        all_inputs_value = []
        all_inputs_active = []
        word_size = model.word_size
        rot_amount = self.description[1] // word_size
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_value.extend(
                [
                    f"{id_link}_value[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
            all_inputs_active.extend(
                [
                    f"{id_link}_active[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        input_len = len(all_inputs_value)
        cp_constraints = []
        for i in range(input_len):
            cp_constraints.append(
                f"constraint {self.id}_active[{i}] = {all_inputs_active[(i - rot_amount) % input_len]};"
            )
            cp_constraints.append(
                f"constraint {self.id}_value[{i}] = {all_inputs_value[(i - rot_amount) % input_len]};"
            )

        return cp_declarations, cp_constraints

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for ROTATE component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: class DummyModel:
            ....:     word_size = 2
            sage: rotate_component = Rotate(0, 0, ['input0'], [list(range(8))], 8, -2)
            sage: rotate_component.cp_xor_differential_first_step_constraints(DummyModel())
            (['array[0..3] of var 0..1: rot_0_0;'],
            ['constraint rot_0_0[0] = input0[1];',
            'constraint rot_0_0[1] = input0[2];',
            'constraint rot_0_0[2] = input0[3];',
            'constraint rot_0_0[3] = input0[0];'])
        """
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        word_size = model.word_size
        rot_amount = abs(self.description[1]) // word_size
        numb_of_inp = len(input_id_link)
        all_inputs = []
        number_of_mix = 0
        is_mix = False
        for i in range(numb_of_inp):
            for j in range(len(input_bit_positions[i]) // word_size):
                all_inputs.append(f"{input_id_link[i]}[{input_bit_positions[i][j * word_size] // word_size}]")
            rem = len(input_bit_positions[i]) % word_size
            if rem != 0:
                rem = word_size - (len(input_bit_positions[i]) % word_size)
                all_inputs.append(f"{output_id_link}_i[{number_of_mix}]")
                number_of_mix += 1
                is_mix = True
                l = 1
                while rem > 0:
                    length = len(input_bit_positions[i + l])
                    del input_bit_positions[i + l][0:rem]
                    rem -= length
                    l += 1
        cp_declarations = [f"array[0..{(self.output_bit_size - 1) // word_size}] of var 0..1: {output_id_link};"]
        if is_mix:
            cp_declarations.append(f"array[0..{number_of_mix - 1}] of var 0..1: {output_id_link}_i;")
        input_len = len(all_inputs)
        if rot_amount == self.description[1]:
            cp_constraints = [
                f"constraint {output_id_link}[{i}] = {all_inputs[(i - rot_amount) % input_len]};"
                for i in range(self.output_bit_size // word_size)
            ]
        else:
            cp_constraints = [
                f"constraint {output_id_link}[{i}] = {all_inputs[(i + rot_amount) % input_len]};"
                for i in range(self.output_bit_size // word_size)
            ]

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        return self.cp_constraints()

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for ROTATE component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..1] of var 0..1: rot_0_0_i;', 'array[0..1] of var 0..1: rot_0_0_o;'], ['constraint rot_0_0_o[0]=rot_0_0_i[1];', 'constraint rot_0_0_o[1]=rot_0_0_i[0];'])
        """
        cp_declarations = [
            f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id}_i;",
            f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id}_o;",
        ]
        output_size = int(self.output_bit_size)
        rot_amount = abs(self.description[1])
        cp_constraints = []
        if rot_amount == self.description[1]:
            for i in range(output_size):
                cp_constraints.append(f"constraint {self.id}_o[{i}]={self.id}_i[{(i - rot_amount) % output_size}];")
        else:
            for i in range(output_size):
                cp_constraints.append(f"constraint {self.id}_o[{i}]={self.id}_i[{(i + rot_amount) % output_size}];")

        return cp_declarations, cp_constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f"  {self.id} = bit_vector_ROTATE([{','.join(params)} ], {self.description[1]})"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_ROTATE({params}, {self.description[1]}, {self.input_bit_size})"]

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        rotate_code = []

        self.select_words(rotate_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        rotate_code.append(
            f"\tWordString *{self.id} = {direction}_{self.description[0]}(input, {abs(self.description[1])});"
        )

        if verbosity:
            self.print_word_values(rotate_code)

        return rotate_code

    def get_word_operation_sign(self, sign, solution):
        output_id_link = self.id
        component_sign = 1
        sign = sign * component_sign
        solution["components_values"][f"{output_id_link}_o"]["sign"] = component_sign
        solution["components_values"][output_id_link] = solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_o"]
        del solution["components_values"][f"{output_id_link}_i"]

        return sign

    def milp_constraints(self, model):
        """
        Return a list of variables and a list of constrains modeling a component of type ROTATE for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = RotateCipher(bit_size=2, parameter=1)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: rotate_component = cipher.component_from_id('rot_0_0')
            sage: variables, constraints = rotate_component.milp_constraints(milp)
            sage: variables
            [('x[plaintext_0]', x_0), ('x[plaintext_1]', x_1), ('x[rot_0_0_0]', x_2), ('x[rot_0_0_1]', x_3)]
            sage: constraints
            [x_2 == x_1, x_3 == x_0]
        """
        x = model.binary_variable
        rotation_step = self.description[1]
        abs_rotation_step = abs(rotation_step)
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []

        if rotation_step < 0:
            tmp = input_vars[:abs_rotation_step]
            input_vars = input_vars[abs_rotation_step:] + tmp
        elif rotation_step > 0:
            tmp = input_vars[-abs_rotation_step:]
            input_vars = tmp + input_vars[:-abs_rotation_step]
        for output_var, input_var in zip(output_vars, input_vars):
            constraints.append(x[output_var] == x[input_var])

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type Rotate for the deterministic
        truncated xor differential model.

        INPUTS:

        - ``component`` -- *dict*, the rotate component in Graph Representation
          of a cipher

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: cipher = RotateCipher(bit_size=4, parameter=4)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: rotate_component = cipher.component_from_id('rot_0_0')
            sage: variables, constraints = rotate_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_word_0_class]', x_0), ('x_class[rot_0_0_word_0_class]', x_1), ('x[plaintext_0]', x_2), ('x[plaintext_1]', x_3), ('x[plaintext_2]', x_4), ('x[plaintext_3]', x_5), ('x[rot_0_0_0]', x_6), ('x[rot_0_0_1]', x_7), ('x[rot_0_0_2]', x_8), ('x[rot_0_0_3]', x_9)]
            sage: constraints
            [x_1 == x_0, x_6 == x_2, x_7 == x_3, x_8 == x_4, x_9 == x_5]
        """
        x_class = model.trunc_wordvar

        rotation_step = self.description[1]
        abs_rotation_word_step = abs(rotation_step) // model.word_size
        constraints = []

        input_class_vars, output_class_vars = self._get_wordwise_input_output_linked_class(model)
        class_variables = [(f"x_class[{var}]", x_class[var]) for var in input_class_vars + output_class_vars]

        output_word_size = self.output_bit_size // model.word_size

        if rotation_step < 0:
            tmp = input_class_vars[:abs_rotation_word_step]
            input_class_vars = input_class_vars[abs_rotation_word_step:] + tmp
        elif rotation_step > 0:
            tmp = input_class_vars[-abs_rotation_word_step:]
            input_class_vars = tmp + input_class_vars[:-abs_rotation_word_step]
        for i in range(output_word_size):
            constraints.append(x_class[output_class_vars[i]] == x_class[input_class_vars[i]])

        bit_variables, bit_constraints = self.milp_constraints(model)

        return class_variables + bit_variables, constraints + bit_constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type Rotate for the deterministic
        truncated xor differential model.

        INPUTS:

        - ``component`` -- *dict*, the rotate component in Graph Representation
          of a cipher

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: cipher = RotateCipher(bit_size=2, parameter=1)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: rotate_component = cipher.component_from_id('rot_0_0')
            sage: variables, constraints = rotate_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_0]', x_0), ('x_class[plaintext_1]', x_1), ('x_class[rot_0_0_0]', x_2), ('x_class[rot_0_0_1]', x_3)]
            sage: constraints
            [x_2 == x_1, x_3 == x_0]
        """
        x_class = model.trunc_binvar

        rotation_step = self.description[1]
        abs_rotation_step = abs(rotation_step)
        input_class_vars, output_class_vars = self._get_input_output_variables()
        class_variables = [(f"x_class[{var}]", x_class[var]) for var in input_class_vars + output_class_vars]
        constraints = []

        if rotation_step < 0:
            tmp = input_class_vars[:abs_rotation_step]
            input_class_vars = input_class_vars[abs_rotation_step:] + tmp
        elif rotation_step > 0:
            tmp = input_class_vars[-abs_rotation_step:]
            input_class_vars = tmp + input_class_vars[:-abs_rotation_step]
        for output_class_var, input_class_var in zip(output_class_vars, input_class_vars):
            constraints.append(x_class[output_class_var] == x_class[input_class_var])

        return class_variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for ROTATE operation in MILP XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = RotateCipher(bit_size=2, parameter=1)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: rotate_component = cipher.component_from_id('rot_0_0')
            sage: variables, constraints = rotate_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[rot_0_0_0_i]', x_0), ('x[rot_0_0_1_i]', x_1), ('x[rot_0_0_0_o]', x_2), ('x[rot_0_0_1_o]', x_3)]
            sage: constraints
            [x_2 == x_1, x_3 == x_0]
        """
        x = model.binary_variable
        rotation_step = self.description[1]
        abs_rotation_step = abs(rotation_step)
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        if rotation_step < 0:
            tmp = input_vars[:abs_rotation_step]
            input_vars = input_vars[abs_rotation_step:] + tmp
        elif rotation_step > 0:
            tmp = input_vars[-abs_rotation_step:]
            input_vars = tmp + input_vars[:-abs_rotation_step]
        for output_var, input_var in zip(output_vars, input_vars):
            constraints.append(x[output_var] == x[input_var])

        return variables, constraints

    def minizinc_constraints(self, model):
        r"""
        Return variables and constraints for the component ROTATE for MINIZINC CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: cipher = RotateCipher(bit_size=2, parameter=1)
            sage: minizinc = MznModel(cipher)
            sage: rotate_component = cipher.component_from_id('rot_0_0')
            sage: _, rotate_mzn_constraints = rotate_component.minizinc_constraints(minizinc)
            sage: rotate_mzn_constraints[0]
            'constraint RRot(array1d(0..2-1, [rot_0_0_x0,rot_0_0_x1]), 1)=array1d(0..2-1, [rot_0_0_y0,rot_0_0_y1]);\n'
        """
        if self.description[0].lower() != "rotate":
            raise ValueError("component must be bitwise rotation")
        input_postfix = model.input_postfix
        output_postfix = model.output_postfix

        var_names = self._define_var(input_postfix, output_postfix, model.data_type)
        rotation_const = self.description[1]
        ninputs = noutputs = self.output_bit_size
        input_vars = [f"{self.id}_{input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{output_postfix}{i}" for i in range(noutputs)]
        input_vars_1 = input_vars
        mzn_input_array_1 = self._create_minizinc_1d_array_from_list(input_vars_1)
        output_vars_1 = output_vars
        mzn_output_array_1 = self._create_minizinc_1d_array_from_list(output_vars_1)

        if rotation_const < 0:
            rotate_mzn_constraints = [
                f"constraint LRot({mzn_input_array_1}, {int(-1 * rotation_const)})={mzn_output_array_1};\n"
            ]
        else:
            rotate_mzn_constraints = [
                f"constraint RRot({mzn_input_array_1}, {int(rotation_const)})={mzn_output_array_1};\n"
            ]

        return var_names, rotate_mzn_constraints

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing ROTATION for SAT CIPHER model

        The list of clauses encodes equalities ensuring that input variables are correctly positioned in the output.
        Each clause represents a logical condition where input variables are mapped to their corresponding output
        positions through rotation.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.sat_constraints()
            (['rot_0_0_0', 'rot_0_0_1'], ['rot_0_0_0 -input_1', 'input_1 -rot_0_0_0', 'rot_0_0_1 -input_0', 'input_0 -rot_0_0_1'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing ROTATION for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        Note that encoding symbols for deterministic truncated XOR differential model
        requires two variables per each symbol.

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.rotate_component.Rotate.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['rot_0_0_0_0', 'rot_0_0_1_0', 'rot_0_0_0_1', 'rot_0_0_1_1'], ['rot_0_0_0_0 -input_1_0', 'input_1_0 -rot_0_0_0_0', 'rot_0_0_1_0 -input_0_0', 'input_0_0 -rot_0_0_1_0', 'rot_0_0_0_1 -input_1_1', 'input_1_1 -rot_0_0_0_1', 'rot_0_0_1_1 -input_0_1', 'input_0_1 -rot_0_0_1_1'])
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        rotation = self.description[1]
        in_ids_0_rotated = in_ids_0[-rotation:] + in_ids_0[:-rotation]
        in_ids_1_rotated = in_ids_1[-rotation:] + in_ids_1[:-rotation]
        constraints = []
        for out_id, in_id in zip(out_ids_0, in_ids_0_rotated):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))
        for out_id, in_id in zip(out_ids_1, in_ids_1_rotated):
            constraints.extend(sat_utils.cnf_equivalent([out_id, in_id]))

        return out_ids_0 + out_ids_1, constraints

    def sat_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing ROTATION for SAT XOR DIFFERENTIAL model

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.rotate_component.Rotate.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.sat_xor_differential_propagation_constraints()
            (['rot_0_0_0', 'rot_0_0_1'], ['rot_0_0_0 -input_1', 'input_1 -rot_0_0_0', 'rot_0_0_1 -input_0', 'input_0 -rot_0_0_1'])
        """
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing ROTATION for SAT XOR LINEAR model

        Note that encoding symbols for deterministic truncated XOR differential model
        requires different encodings for input and ouput variables.

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.rotate_component.Rotate.sat_constraints>` for the model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.sat_xor_linear_mask_propagation_constraints()
            (['rot_0_0_0_i', 'rot_0_0_1_i', 'rot_0_0_0_o', 'rot_0_0_1_o'], ['rot_0_0_0_o -rot_0_0_1_i', 'rot_0_0_1_i -rot_0_0_0_o', 'rot_0_0_1_o -rot_0_0_0_i', 'rot_0_0_0_i -rot_0_0_1_o'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]]))
        result = input_bit_ids + output_bit_ids, constraints

        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing ROTATION for SMT CIPHER model

        The list of asserts encodes equalities ensuring that input variables are correctly positioned in the output.
        Each assert represents a condition where input variables are mapped to their corresponding output
        positions through rotation.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.smt_constraints()
            (['rot_0_0_0', 'rot_0_0_1'], ['(assert (= rot_0_0_0 input_1))', '(assert (= rot_0_0_1 input_0))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing ROTATION for SMT CIPHER model

        .. SEEALSO::

            :obj:`smt_constraints() <components.rotate_component.Rotate.smt_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.smt_xor_differential_propagation_constraints()
            (['rot_0_0_0', 'rot_0_0_1'], ['(assert (= rot_0_0_0 input_1))', '(assert (= rot_0_0_1 input_0))'])
        """
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing ROTATION for SMT XOR LINEAR model

        Note that encoding symbols for deterministic truncated XOR differential model
        requires different encodings for input and ouput variables.

        .. SEEALSO::

            :obj:`smt_constraints() <components.rotate_component.Rotate.smt_constraints>` for the model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.rotate_component import Rotate
            sage: rotate_component = Rotate(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: rotate_component.smt_xor_linear_mask_propagation_constraints()
            (['rot_0_0_0_i', 'rot_0_0_1_i', 'rot_0_0_0_o', 'rot_0_0_1_o'], ['(assert (= rot_0_0_0_o rot_0_0_1_i))', '(assert (= rot_0_0_1_o rot_0_0_0_i))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(out_suffix)
        rotation = self.description[1]
        input_bit_ids_rotated = input_bit_ids[-rotation:] + input_bit_ids[:-rotation]
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids_rotated[i]])
            constraints.append(smt_utils.smt_assert(equation))
        result = input_bit_ids + output_bit_ids, constraints

        return result
