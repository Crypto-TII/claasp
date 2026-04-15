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
from claasp.cipher_modules.models.cp.cp_component_build_result import CpComponentBuildResult
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils
from claasp.name_mappings import WORD_OPERATION


class SHIFT(Component):
    """
    Construct a SHIFT component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``parameter`` -- **integer**; operation parameter (for example shift/rotation amount). Negative values are allowed when semantics supports them.

    EXAMPLES::

        sage: from claasp.components.shift_component import SHIFT
        sage: component = SHIFT(0, 0, ['input'], [[0, 1]], 2, -1)
        sage: print(component.id)
        shift_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['SHIFT', -1]
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
        component_id = f"shift_{current_round_number}_{current_round_number_of_components}"
        component_type = WORD_OPERATION
        description = ["SHIFT", parameter]
        component_input = Input(output_bit_size, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for bitwise SHIFT.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = ShiftCipher(bit_size=2, parameter=1)
            sage: shift_component = cipher.get_component_from_id('shift_0_0')
            sage: algebraic = AlgebraicModel(cipher)
            sage: shift_component.algebraic_polynomials(algebraic)
            [shift_0_0_y0, shift_0_0_y1 + shift_0_0_x0]
        """
        if self.description[0].lower() != "shift":
            raise ValueError("component must be bitwise shift")

        ninputs = noutputs = self.output_bit_size
        shift_constant = self.description[1] % noutputs
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]
        ring_R = model.ring()
        x = list(map(ring_R, input_vars))
        y = list(map(ring_R, output_vars))

        polynomials = [y[i] for i in range(shift_constant)] + [
            y[shift_constant:][i] + x[i] for i in range(noutputs - shift_constant)
        ]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for shift in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.cms_constraints()
            (['shift_0_0_0', 'shift_0_0_1'], ['-shift_0_0_0', 'shift_0_0_1 -input_0', 'input_0 -shift_0_0_1'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for SHIFT component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: result = shift_component.cp_constraints()
            sage: result.declarations
            []
            sage: result.constraints
            ['constraint shift_0_0[0] = 0;', 'constraint shift_0_0[1] = input[0];']
        """
        shift_amount = abs(self.description[1])
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        if shift_amount == self.description[1]:
            cp_constraints = [f"constraint {self.id}[{i}] = 0;" for i in range(shift_amount)]
            cp_constraints.extend(
                [
                    f"constraint {self.id}[{i}] = {all_inputs[i - shift_amount]};"
                    for i in range(shift_amount, self.output_bit_size)
                ]
            )
        else:
            cp_constraints = [
                f"constraint {self.id}[{i}] = {all_inputs[i + shift_amount]};"
                for i in range(self.output_bit_size - shift_amount)
            ]
            cp_constraints.extend(
                [
                    f"constraint {self.id}[{i}] = 0;"
                    for i in range(self.output_bit_size - shift_amount, self.output_bit_size)
                ]
            )

        return CpComponentBuildResult(cp_declarations, cp_constraints)

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self, context, state):
        return self.cp_constraints()

    def cp_inverse_constraints(self):
        """
        Return a list of CP declarations and a list of CP constraints for SHIFT component for CP INVERSE CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: result = shift_component.cp_inverse_constraints()
            sage: result.declarations
            []
            sage: result.constraints
            ['constraint shift_0_0_inverse[0] = 0;', 'constraint shift_0_0_inverse[1] = input[0];']
        """
        shift_amount = abs(self.description[1])
        cp_declarations = []
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])
        if shift_amount == self.description[1]:
            cp_constraints = [f"constraint {self.id}_inverse[{i}] = 0;" for i in range(shift_amount)]
            cp_constraints.extend(
                [
                    f"constraint {self.id}_inverse[{i}] = {all_inputs[i - shift_amount]};"
                    for i in range(shift_amount, self.output_bit_size)
                ]
            )
        else:
            cp_constraints = [
                f"constraint {self.id}_inverse[{i}] = {all_inputs[i + shift_amount]};"
                for i in range(self.output_bit_size - shift_amount)
            ]
            cp_constraints.extend(
                [
                    f"constraint {self.id}_inverse[{i}] = 0;"
                    for i in range(self.output_bit_size - shift_amount, self.output_bit_size)
                ]
            )

        return CpComponentBuildResult(cp_declarations, cp_constraints)

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, context, state):
        """
        Return a list of CP declarations and a list of CP constraints for shift component.

        This is for CP wordwise deterministic truncated xor differential trail search.

        INPUT:

        - ``context`` -- a ``CpBuildContext`` (read-only build configuration)
        - ``state`` -- ``CpBuildState`` (mutable accumulator for build state)

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: class DummyContext:
            ....:     word_size = 2
            sage: shift_component = SHIFT(0, 18, ['sbox_0_2'], [list(range(4))], 4, -2)
            sage: result = shift_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyContext(), None)
            sage: result.declarations
            []
            sage: result.constraints
            ['constraint shift_0_18_active[0] = sbox_0_2_active[1];', 'constraint shift_0_18_active[1] = 0;', 'constraint shift_0_18_value[0] = sbox_0_2_active[1];', 'constraint shift_0_18_value[1] = 0;']
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        word_size = context.word_size
        shift_amount = abs(self.description[1]) // word_size
        all_inputs_active = []
        all_inputs_value = []
        cp_declarations = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_active.extend(
                [
                    f"{id_link}_active[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_value.extend(
                [
                    f"{id_link}_value[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        if shift_amount == self.description[1]:
            cp_constraints = [f"constraint {output_id_link}_active[{i}] = 0;" for i in range(shift_amount)]
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}_active[{i}] = {all_inputs_active[i - shift_amount]};"
                    for i in range(shift_amount, output_size // word_size)
                ]
            )
            cp_constraints.extend([f"constraint {output_id_link}_value[{i}] = 0;" for i in range(shift_amount)])
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}_value[{i}] = {all_inputs_active[i - shift_amount]};"
                    for i in range(shift_amount, output_size // word_size)
                ]
            )
        else:
            cp_constraints = [
                f"constraint {output_id_link}_active[{i}] = {all_inputs_active[i + shift_amount]};"
                for i in range(output_size // word_size - shift_amount)
            ]
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}_active[{i}] = 0;"
                    for i in range(output_size // word_size - shift_amount, output_size // word_size)
                ]
            )
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}_value[{i}] = {all_inputs_active[i + shift_amount]};"
                    for i in range(output_size // word_size - shift_amount)
                ]
            )
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}_value[{i}] = 0;"
                    for i in range(output_size // word_size - shift_amount, output_size // word_size)
                ]
            )

        return CpComponentBuildResult(cp_declarations, cp_constraints)

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for SHIFT component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: class DummyModel:
            ....:     word_size = 2
            sage: shift_component = SHIFT(0, 18, ['input0'], [list(range(4))], 4, -2)
            sage: result = shift_component.cp_xor_differential_first_step_constraints(DummyModel())
            sage: result.declarations
            ['array[0..1] of var 0..1: shift_0_18;']
            sage: result.constraints
            ['constraint shift_0_18[0] = input0[1];', 'constraint shift_0_18[1] = 0;']
        """
        output_size = int(self.output_bit_size)
        input_id_link = self.input_id_links
        output_id_link = self.id
        input_bit_positions = self.input_bit_positions
        shift_amount = abs(self.description[1]) // model.word_size
        all_inputs = []
        number_of_mix = 0
        is_mix = False
        numb_of_inp = len(input_id_link)
        for i in range(numb_of_inp):
            for j in range(len(input_bit_positions[i]) // model.word_size):
                all_inputs.append(
                    f"{input_id_link[i]}[{input_bit_positions[i][j * model.word_size] // model.word_size}]"
                )
            rem = len(input_bit_positions[i]) % model.word_size
            if rem != 0:
                rem = model.word_size - (len(input_bit_positions[i]) % model.word_size)
                all_inputs.append(f"{output_id_link}_i[{number_of_mix}]")
                number_of_mix += 1
                is_mix = True
                l = 1
                while rem > 0:
                    length = len(input_bit_positions[i + l])
                    del input_bit_positions[i + l][0:rem]
                    rem -= length
                    l += 1
        cp_declarations = [f"array[0..{(output_size - 1) // model.word_size}] of var 0..1: {output_id_link};"]

        if is_mix:
            cp_declarations.append(f"array[0..{number_of_mix - 1}] of var 0..1: {output_id_link}_i;")
        if shift_amount == self.description[1]:
            cp_constraints = [f"constraint {output_id_link}[{i}] = 0;" for i in range(shift_amount)]
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}[{i}] = {all_inputs[i - shift_amount]};"
                    for i in range(shift_amount, output_size // model.word_size)
                ]
            )
        else:
            cp_constraints = [
                f"constraint {output_id_link}[{i}] = {all_inputs[i + shift_amount]};"
                for i in range(output_size // model.word_size - shift_amount)
            ]
            cp_constraints.extend(
                [
                    f"constraint {output_id_link}[{i}] = 0;"
                    for i in range(output_size // model.word_size - shift_amount, output_size // model.word_size)
                ]
            )

        return CpComponentBuildResult(cp_declarations, cp_constraints)

    def cp_xor_differential_propagation_constraints(self, context, state):
        return self.cp_constraints()

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_linear_mask_propagation_constraints(self, context, state):
        """
        Return a list of Cp declarations and a list of Cp constraints for SHIFT component for CP xor linear model.

        INPUT:

        - ``context`` -- a ``CpBuildContext`` (read-only build configuration)
        - ``state`` -- ``CpBuildState`` (mutable accumulator for build state)

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.cp_xor_linear_mask_propagation_constraints(None, None)
            CpComponentBuildResult(declarations=['array[0..1] of var 0..1: shift_0_0_i;', 'array[0..1] of var 0..1: shift_0_0_o;'], constraints=['constraint shift_0_0_i[1]=0;', 'constraint shift_0_0_o[1]=shift_0_0_i[0];'], metadata={})
        """
        output_size = self.output_bit_size
        output_id_link = self.id
        shift_amount = abs(self.description[1])
        cp_declarations = [
            f"array[0..{output_size - 1}] of var 0..1: {output_id_link}_i;",
            f"array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;",
        ]
        cp_constraints = []
        if shift_amount == self.description[1]:
            for i in range(output_size - shift_amount, output_size):
                cp_constraints.append(f"constraint {output_id_link}_i[{i}]=0;")
            for i in range(shift_amount, output_size):
                cp_constraints.append(f"constraint {output_id_link}_o[{i}]={output_id_link}_i[{i - shift_amount}];")
        else:
            for i in range(output_size - shift_amount):
                cp_constraints.append(f"constraint {output_id_link}_o[{i}]={output_id_link}_i[{i + shift_amount}];")
            for i in range(shift_amount):
                cp_constraints.append(f"constraint {output_id_link}_i[{i}]=0;")

        return CpComponentBuildResult(cp_declarations, cp_constraints)

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f"  {self.id} = bit_vector_SHIFT([{','.join(params)} ], {self.description[1]})"]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_SHIFT({params}, {self.description[1]})"]

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        shift_code = []

        self.select_words(shift_code, word_size)
        wordstring_variables.append(self.id)
        direction = "RIGHT" if self.description[1] >= 0 else "LEFT"
        shift_code.append(
            f"\tWordString *{self.id} = {direction}_{self.description[0]}(input, {abs(self.description[1])});"
        )

        if verbosity:
            self.print_word_values(shift_code)

        return shift_code

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
        Return a list of variables and a list of constrains modeling a component of type SHIFT for MILP CIPHER model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = ShiftCipher(bit_size=2, parameter=1)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: shift_component = cipher.get_component_from_id('shift_0_0')
            sage: variables, constraints = shift_component.milp_constraints(milp)
            sage: variables
            [('x[plaintext_0]', x_0),
            ('x[plaintext_1]', x_1),
            ('x[shift_0_0_0]', x_2),
            ('x[shift_0_0_1]', x_3)]
            sage: constraints
            [x_2 == 0, x_3 == x_0]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        shift_step = self.description[1]
        abs_shift_step = abs(shift_step)

        if shift_step < 0:
            input_vars = input_vars[abs_shift_step:] + [0] * abs_shift_step
        elif shift_step > 0:
            input_vars = [0] * abs_shift_step + input_vars[:-abs_shift_step]

        for i in range(output_bit_size):
            if input_vars[i] == 0:
                constraints.append(x[output_vars[i]] == 0)
            else:
                constraints.append(x[output_vars[i]] == x[input_vars[i]])

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type Shift.

        EXAMPLE::

            sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
            sage: cipher = ShiftCipher(bit_size=2, parameter=1)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: shift_component = cipher.component_from(0, 0)
            sage: variables, constraints = shift_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_0]', x_0),
            ('x_class[plaintext_1]', x_1),
            ('x_class[shift_0_0_0]', x_2),
            ('x_class[shift_0_0_1]', x_3)]
            sage: constraints
            [x_2 == 0, x_3 == x_0]

        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        shift_step = self.description[1]
        abs_shift_step = abs(shift_step)

        if shift_step < 0:
            input_vars = input_vars[abs_shift_step:] + [0] * abs_shift_step
        elif shift_step > 0:
            input_vars = [0] * abs_shift_step + input_vars[:-abs_shift_step]

        for i in range(output_bit_size):
            if input_vars[i] == 0:
                constraints.append(x_class[output_vars[i]] == 0)
            else:
                constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constrains modeling a component of type Shift.

        EXAMPLE::

            sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
            sage: cipher = ShiftCipher(bit_size=4, parameter=-4)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 18, ['plaintext'], [list(range(4))], 4, -4)
            sage: variables, constraints = shift_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_word_0_class]', x_0),
            ('x_class[shift_0_18_word_0_class]', x_1),
            ('x[plaintext_0]', x_2),
            ('x[plaintext_1]', x_3),
            ('x[plaintext_2]', x_4),
            ('x[plaintext_3]', x_5),
            ('x[shift_0_18_0]', x_6),
            ('x[shift_0_18_1]', x_7),
            ('x[shift_0_18_2]', x_8),
            ('x[shift_0_18_3]', x_9)]
            sage: constraints
            [x_1 == 0, x_6 == 0, x_7 == 0, x_8 == 0, x_9 == 0]

        """
        x_class = model.trunc_wordvar

        input_vars, output_vars = self._get_wordwise_input_output_linked_class(model)
        class_variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        output_word_size = self.output_bit_size // model.word_size
        shift_step = self.description[1]
        abs_shift_word_step = abs(shift_step) // model.word_size

        if shift_step < 0:
            input_vars = input_vars[abs_shift_word_step:] + [0] * abs_shift_word_step
        elif shift_step > 0:
            input_vars = [0] * abs_shift_word_step + input_vars[:-abs_shift_word_step]

        for i in range(output_word_size):
            if input_vars[i] == 0:
                constraints.append(x_class[output_vars[i]] == 0)
            else:
                constraints.append(x_class[output_vars[i]] == x_class[input_vars[i]])

        bit_variables, bit_constraints = self.milp_constraints(model)

        return class_variables + bit_variables, constraints + bit_constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for SHIFT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = ShiftCipher(bit_size=2, parameter=1)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: shift_component = cipher.get_component_from_id('shift_0_0')
            sage: variables, constraints = shift_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[shift_0_0_0_i]', x_0), ('x[shift_0_0_1_i]', x_1), ('x[shift_0_0_0_o]', x_2), ('x[shift_0_0_1_o]', x_3)]
            sage: constraints
            [x_1 == 0, x_3 == x_0]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        output_bit_size = self.output_bit_size
        shift_step = self.description[1]
        abs_shift_step = abs(shift_step)

        if shift_step < 0:
            for i in range(abs_shift_step):
                constraints.append(x[input_vars[i]] == 0)
            for i in range(output_bit_size - abs_shift_step):
                constraints.append(x[output_vars[i]] == x[input_vars[i + abs_shift_step]])
        elif shift_step > 0:
            for i in range(output_bit_size - abs_shift_step, output_bit_size):
                constraints.append(x[input_vars[i]] == 0)
            for i in range(abs_shift_step, output_bit_size):
                constraints.append(x[output_vars[i]] == x[input_vars[i - abs_shift_step]])

        return variables, constraints

    def minizinc_constraints(self, model):
        r"""
        Return variables and constraints for the component SHIFT for MINIZINC CIPHER model.

        INPUT:

        - ``model`` -- **model object**;  a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
            sage: from claasp.cipher_modules.models.cp.mzn_model import MznModel
            sage: cipher = ShiftCipher(bit_size=2, parameter=1)
            sage: minizinc = MznModel(cipher)
            sage: shift_component = cipher.get_component_from_id('shift_0_0')
            sage: result = shift_component.minizinc_constraints(minizinc)
            sage: result.declarations
            ['var bool: shift_0_0_x0;', 'var bool: shift_0_0_x1;', 'var bool: shift_0_0_y0;', 'var bool: shift_0_0_y1;']
            sage: result.constraints
            ['constraint RSHIFT(array1d(0..2-1, [shift_0_0_x0,shift_0_0_x1]), 1)=array1d(0..2-1, [shift_0_0_y0,shift_0_0_y1]);\n']
        """
        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)
        shift_const = self.description[1]
        ninputs = noutputs = self.output_bit_size
        input_vars = [self.id + "_" + model.input_postfix + str(i) for i in range(ninputs)]
        output_vars = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        input_vars_1 = input_vars
        mzn_input_array_1 = self._create_minizinc_1d_array_from_list(input_vars_1)
        output_vars_1 = output_vars
        mzn_output_array_1 = self._create_minizinc_1d_array_from_list(output_vars_1)

        if shift_const < 0:
            shift_mzn_constraints = [
                f"constraint LSHIFT({mzn_input_array_1}, {int(-1 * shift_const)})={mzn_output_array_1};\n"
            ]
        else:
            shift_mzn_constraints = [
                f"constraint RSHIFT({mzn_input_array_1}, {int(shift_const)})={mzn_output_array_1};\n"
            ]

        return CpComponentBuildResult(var_names, shift_mzn_constraints)

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        return self.minizinc_constraints(model)

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing SHIFT for SAT CIPHER model.

        The list of clauses encodes equalities ensuring that input variables are correctly positioned in the output
        during the shift operation. Each clause represents a logical condition where input variables are mapped to their
        corresponding output positions through the shift. Additionally, output variables that do not correspond to an
        input variable are constrained to zero, ensuring a valid state in the resulting configuration.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.sat_constraints()
            (['shift_0_0_0', 'shift_0_0_1'], ['-shift_0_0_0', 'shift_0_0_1 -input_0', 'input_0 -shift_0_0_1'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            for i in range(output_bit_len - shift_amount):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i + shift_amount]]))
            for i in range(output_bit_len - shift_amount, output_bit_len):
                constraints.append(f"-{output_bit_ids[i]}")
        else:
            for i in range(shift_amount):
                constraints.append(f"-{output_bit_ids[i]}")
            for i in range(shift_amount, output_bit_len):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i - shift_amount]]))

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing SHIFT for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        Note that encoding symbols for deterministic truncated XOR differential model
        requires two variables per each symbol.

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.shift_component.SHIFT.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['shift_0_0_0_0', 'shift_0_0_1_0', 'shift_0_0_0_1', 'shift_0_0_1_1'], ['-shift_0_0_0_0', '-shift_0_0_0_1', 'shift_0_0_1_0 -input_0_0', 'input_0_0 -shift_0_0_1_0', 'shift_0_0_1_1 -input_0_1', 'input_0_1 -shift_0_0_1_1'])
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        out_len, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            for i in range(out_len - shift_amount):
                constraints.extend(sat_utils.cnf_equivalent([out_ids_0[i], in_ids_0[i + shift_amount]]))
                constraints.extend(sat_utils.cnf_equivalent([out_ids_1[i], in_ids_1[i + shift_amount]]))
            for i in range(out_len - shift_amount, out_len):
                constraints.append(f"-{out_ids_0[i]}")
                constraints.append(f"-{out_ids_1[i]}")
        else:
            for i in range(shift_amount):
                constraints.append(f"-{out_ids_0[i]}")
                constraints.append(f"-{out_ids_1[i]}")
            for i in range(shift_amount, out_len):
                constraints.extend(sat_utils.cnf_equivalent([out_ids_0[i], in_ids_0[i - shift_amount]]))
                constraints.extend(sat_utils.cnf_equivalent([out_ids_1[i], in_ids_1[i - shift_amount]]))

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing SHIFT for SAT XOR DIFFERENTIAL model.

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.shift_component.SHIFT.sat_constraints>` for the model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.sat_xor_differential_propagation_constraints()
            (['shift_0_0_0', 'shift_0_0_1'], ['-shift_0_0_0', 'shift_0_0_1 -input_0', 'input_0 -shift_0_0_1'])
        """
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing SHIFT for SAT XOR LINEAR model

        Note that encoding symbols for deterministic truncated XOR differential model
        requires different encodings for input and ouput variables.

        .. SEEALSO::

            - :ref:`sat-standard` for the format.
            - :obj:`sat_constraints() <components.shift_component.SHIFT.sat_constraints>` for the model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.sat_xor_linear_mask_propagation_constraints()
            (['shift_0_0_0_i', 'shift_0_0_1_i', 'shift_0_0_0_o', 'shift_0_0_1_o'], ['shift_0_0_1_o -shift_0_0_0_i', 'shift_0_0_0_i -shift_0_0_1_o', '-shift_0_0_1_i'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            constraints.extend([f"-{input_bit_ids[i]}" for i in range(shift_amount)])
            for i in range(output_bit_len - shift_amount):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i + shift_amount]]))
        else:
            for i in range(shift_amount, output_bit_len):
                constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids[i - shift_amount]]))
            constraints.extend([f"-{input_bit_ids[i]}" for i in range(output_bit_len - shift_amount, output_bit_len)])
        result = input_bit_ids + output_bit_ids, constraints

        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing SHIFT for SMT CIPHER model

        The list of asserts encodes equalities ensuring that input variables are correctly positioned in the output
        during the shift operation. Each clause represents a logical condition where input variables are mapped to their
        corresponding output positions through the shift. Additionally, output variables that do not correspond to an
        input variable are constrained to zero, ensuring a valid state in the resulting configuration. Note that, it is
        not an equality using boolean False, instead, it has been encoded in a CNF fashion.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.smt_constraints()
            (['shift_0_0_0', 'shift_0_0_1'], ['(assert (not shift_0_0_0))', '(assert (= shift_0_0_1 input_0))'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            for i in range(output_bit_len - shift_amount):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i + shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))
            for i in range(output_bit_len - shift_amount, output_bit_len):
                constraints.append(smt_utils.smt_assert(smt_utils.smt_not(output_bit_ids[i])))
        else:
            for i in range(shift_amount):
                constraints.append(smt_utils.smt_assert(smt_utils.smt_not(output_bit_ids[i])))
            for i in range(shift_amount, output_bit_len):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i - shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing SHIFT for SMT XOR DIFFERENTIAL model

        .. SEEALSO::

            :obj:`smt_constraints() <components.shift_component.SHIFT.smt_constraints>`.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.smt_xor_differential_propagation_constraints()
            (['shift_0_0_0', 'shift_0_0_1'], ['(assert (not shift_0_0_0))', '(assert (= shift_0_0_1 input_0))'])
        """
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing SHIFT for SMT XOR LINEAR model

        Note that encoding symbols for deterministic truncated XOR differential model
        requires different encodings for input and ouput variables.

        .. SEEALSO::

            :obj:`smt_constraints() <components.shift_component.SHIFT.smt_constraints>`.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.shift_component import SHIFT
            sage: shift_component = SHIFT(0, 0, ['input'], [[0, 1]], 2, 1)
            sage: shift_component.smt_xor_linear_mask_propagation_constraints()
            (['shift_0_0_0_i', 'shift_0_0_1_i', 'shift_0_0_0_o', 'shift_0_0_1_o'], ['(assert (= shift_0_0_1_o shift_0_0_0_i))', '(assert (not shift_0_0_1_i))'])
        """
        _, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        shift_amount = self.description[1]
        constraints = []
        if shift_amount < 0:
            shift_amount = -shift_amount
            constraints.extend([smt_utils.smt_assert(smt_utils.smt_not(input_bit_ids[i])) for i in range(shift_amount)])
            for i in range(output_bit_len - shift_amount):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i + shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))
        else:
            for i in range(shift_amount, output_bit_len):
                equation = smt_utils.smt_equivalent((output_bit_ids[i], input_bit_ids[i - shift_amount]))
                constraints.append(smt_utils.smt_assert(equation))
            constraints.extend(
                [
                    smt_utils.smt_assert(smt_utils.smt_not(input_bit_ids[i]))
                    for i in range(output_bit_len - shift_amount, output_bit_len)
                ]
            )
        result = input_bit_ids + output_bit_ids, constraints

        return result
