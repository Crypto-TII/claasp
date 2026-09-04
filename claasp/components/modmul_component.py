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


from claasp.components.modular_component import Modular
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.cipher_modules.models.milp.utils import utils as milp_utils


class ModMul(Modular):
    """
    Construct a modular multiplication component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``modulus`` -- **integer**; modulus used by modular arithmetic operations. Must be greater than ``0``.

    NOTE:

        The number of operands is automatically inferred as
        ``sum(len(p) for p in input_bit_positions) / output_bit_size``.
        Multiple operands are fully supported: the result is computed as a left-to-right sequential
        multiplication ``(a0 * a1 * a2 * ...) mod 2^output_bit_size``.
        The deterministic truncated XOR differential models, SAT and MILP, support 2 operands only,
        with modulus ``2^output_bit_size``.

    EXAMPLES::

        sage: from claasp.components.modmul_component import ModMul
        sage: component = ModMul(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 2)
        sage: print(component.id)
        modmul_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)  # 4 total bits / output_bit_size 2 = 2 operands
        ['MODMUL', 2, 2]
        sage: component3 = ModMul(0, 1, ['a', 'b', 'c'], [[0, 1], [0, 1], [0, 1]], 2, 4)
        sage: print(component3.description)  # 6 total bits / output_bit_size 2 = 3 operands
        ['MODMUL', 3, 4]
    """

    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        modulus,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "modmul",
            modulus,
        )

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [
            f"  {self.id} = bit_vector_MODMUL([{','.join(params)} ], {self.description[1]}, {self.output_bit_size})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        return [f"  {self.id} = byte_vector_MODMUL({params})"]

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Returns a list of variables and a list of clauses for modular multiplication component
        in deterministic truncated XOR differential model.

        This overrides the model inherited from :class:`Modular`, whose carry pivot is valid for an
        addition but unsound for a product. The model accumulates the activity of the operands as a
        running OR from the least significant bit upwards. The constraints are:
            - 0, for every output bit below the lowest active or unknown operand bit;
            - ? (unknown), for every output bit from that position upwards;

        Note that encoding symbols for deterministic truncated XOR differential model
        requires two variables per each symbol.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        .. WARNING::

            This method supports 2 operands only, with modulus ``2^output_bit_size``.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.modmul_component import ModMul
            sage: modmul_component = ModMul(0, 0, ['plaintext', 'key'], [list(range(4)), list(range(4))], 4, 16)
            sage: output_ids, constraints = modmul_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            sage: len(output_ids)
            8
            sage: constraints[11]
            '-modmul_0_0_2_0 plaintext_2_0 plaintext_2_1 key_2_0 key_2_1 modmul_0_0_3_0'
            sage: constraints[-1]
            '-modmul_0_0_0_1'
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        out_ids_0, out_ids_1 = self._generate_output_double_ids()
        out_len = self.output_bit_size
        constraints = []
        # Accumulated activity (running OR) from the least significant bit (index out_len-1) up to the most
        # significant (index 0): out_ids_0[j] marks "unknown" iff some operand bit at index >= j is
        # active or unknown. out_ids_1[j] is always 0, so no output bit is ever a determined 1.
        for j in range(out_len - 1, -1, -1):
            activity = [in_ids_0[j], in_ids_1[j], in_ids_0[j + out_len], in_ids_1[j + out_len]]
            if j < out_len - 1:
                activity = activity + [out_ids_0[j + 1]]
            constraints.extend(sat_utils.cnf_or(out_ids_0[j], activity))
            constraints.append(f"-{out_ids_1[j]}")
        return out_ids_0 + out_ids_1, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints for modular multiplication component
        in deterministic truncated XOR differential model.

        This overrides the model inherited from :class:`Modular`, whose carry pivot is valid for an
        addition but unsound for a product. Each bit is an integer in ``{0, 1, 2}``, with
        ``0 = inactive``, ``1 = active`` and ``2 = unknown``. The activity of the operands is
        accumulated as a running OR from the least significant bit upwards, and every output bit is
        set to twice that accumulated flag. The constraints are:
            - 0, for every output bit below the lowest active or unknown operand bit;
            - 2 (unknown), for every output bit from that position upwards;
            - no output bit is ever a determined 1.

        .. WARNING::

            This method supports 2 operands only, with modulus ``2^output_bit_size``.

        INPUTS:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.cipher import Cipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
            sage: class DummyMul(Cipher):
            ....:     def __init__(self):
            ....:         super().__init__('dummy_mul', BLOCK_CIPHER, [INPUT_PLAINTEXT, INPUT_KEY], [4, 4], 4)
            ....:         self.add_round()
            ....:         self.add_modmul_component([INPUT_PLAINTEXT, INPUT_KEY], [list(range(4)), list(range(4))], 4, 16)
            ....:         self.add_cipher_output_component(['modmul_0_0'], [list(range(4))], 4)
            sage: cipher = DummyMul()
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: modmul = cipher.component_from_id('modmul_0_0')
            sage: variables, constraints = modmul.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: len(variables)
            12
        """
        x_class = model.trunc_binvar
        input_vars, output_vars = self._get_input_output_variables()
        n = len(output_vars)
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]

        # big-M for the ">= 1" indicators; class values lie in [0, 2], so max + 2 is enough
        big_m = model._model.get_max(x_class) + 2
        constraints = []

        # a_j = 1 iff operand 1 or operand 2 is active or unknown (class >= 1) at index j
        activity = []
        for j in range(n):
            a_x, c_x = milp_utils.milp_geq(model, x_class[input_vars[j]], 1, big_m)
            a_y, c_y = milp_utils.milp_geq(model, x_class[input_vars[j + n]], 1, big_m)
            constraints.extend(c_x)
            constraints.extend(c_y)
            a_j = model.binary_variable[f"a_{self.id}_{j}"]
            # a_j = a_x OR a_y
            constraints.append(a_j >= a_x)
            constraints.append(a_j >= a_y)
            constraints.append(a_j <= a_x + a_y)
            activity.append(a_j)

        # acc_j = a_j OR ... OR a_{n-1}, accumulated from the least significant bit (index n-1)
        # upwards. Each output bit is set to 2 * acc_j, hence 0 or unknown, never a determined 1.
        acc_prev = None
        for j in range(n - 1, -1, -1):
            acc_j = model.binary_variable[f"A_{self.id}_{j}"]
            if j == n - 1:
                constraints.append(acc_j == activity[j])
            else:
                # acc_j = a_j OR acc_{j+1}
                constraints.append(acc_j >= activity[j])
                constraints.append(acc_j >= acc_prev)
                constraints.append(acc_j <= activity[j] + acc_prev)
            acc_prev = acc_j
            constraints.append(x_class[output_vars[j]] == 2 * acc_j)

        return variables, constraints
