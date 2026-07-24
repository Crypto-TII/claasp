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
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.component import Component
from claasp.input import Input
from claasp.name_mappings import CONSTANT


def constant_to_repr(val, output_size):
    """
    Convert a constant literal into the byte-oriented representation used by
    byte-based vectorized evaluation.

    If the literal representation contains more bits than ``output_size``, the
    most-significant ``output_size`` bits are kept (scalar-compatible behavior).

    For ``0x`` and ``0b`` literals, the represented width is taken from the
    literal itself:

    - ``0x1234`` is treated as a 16-bit value (``0001 0010 0011 0100``)
    - ``0b1001000110100`` is treated as a 13-bit value

    EXAMPLES::

        sage: from claasp.components.constant_component import constant_to_repr
        sage: constant_to_repr("0x1000", 12)
        [1, 0]
        sage: # 0x1234 is interpreted as 16 bits: 0001 0010 0011 0100
        sage: constant_to_repr("0x1234", 5)
        [2]
        sage: # Same numeric value, but explicit 13-bit binary literal
        sage: constant_to_repr("0b1001000110100", 5)
        [18]
        sage: constant_to_repr("0b101100", 4)
        [11]
    """
    _val = int(val, 0)
    val_str = str(val).lower()
    if val_str.startswith("0x"):
        represented_bits = (len(val_str) - 2) * 4
    elif val_str.startswith("0b"):
        represented_bits = len(val_str) - 2
    else:
        represented_bits = _val.bit_length()

    if represented_bits > output_size:
        _val >>= represented_bits - output_size

    if output_size > 0:
        _val &= (1 << output_size) - 1

    s = output_size
    if s % 8 != 0:
        s += 8 - (s % 8)
    ret = [(_val >> s - (8 * (i + 1))) & 0xFF for i in range(s // 8)]

    return ret


class Constant(Component):
    """
    Construct a constant component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``value`` -- **integer**; constant value encoded by the component.

    EXAMPLES::

        sage: from claasp.components.constant_component import Constant
        sage: component = Constant(0, 0, 7, 0x8)
        sage: print(component.id)
        constant_0_0
        sage: print(component.type)
        constant
        sage: print(component.description)
        ['0b0001000']
    """
    def __init__(self, current_round_number, current_round_number_of_components, output_bit_size, value):
        component_id = f"{CONSTANT}_{current_round_number}_{current_round_number_of_components}"
        component_type = CONSTANT
        if output_bit_size % 4 == 0:
            description = [f"{value:#0{(output_bit_size // 4) + 2}x}"]
        else:
            description = [f"{value:#0{output_bit_size + 2}b}"]
        component_input = Input(0, [""], [[]])
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for CONSTANT addition.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = ConstantCipher(output_bit_size=4, value=0x1)
            sage: constant_component = cipher.component_from_id('constant_0_0')
            sage: algebraic = AlgebraicModel(cipher)
            sage: constant_component.algebraic_polynomials(algebraic)
            [constant_0_0_y0 + 1, constant_0_0_y1, constant_0_0_y2, constant_0_0_y3]
        """
        noutputs = self.output_bit_size
        constant = int(self.description[0], 16)

        ring_R = model.ring()
        y = list(map(ring_R, [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]))

        b = list(map(int, reversed(bin(constant)[2:])))
        b += [0] * (noutputs - len(b))

        polynomials = [y[i] + b[i] for i in range(noutputs)]

        return polynomials

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for a CONSTANT in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.cms_constraints()
            (['constant_0_0_0', 'constant_0_0_1', 'constant_0_0_2', 'constant_0_0_3'], ['-constant_0_0_0', '-constant_0_0_1', '-constant_0_0_2', 'constant_0_0_3'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.sat_xor_differential_propagation_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_xor_linear_mask_propagation_constraints()

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for CONSTANT component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.cp_constraints()
            (['array[0..3] of var 0..1: constant_0_0;'], ['constraint constant_0_0[0] = 0;', 'constraint constant_0_0[1] = 0;', 'constraint constant_0_0[2] = 0;', 'constraint constant_0_0[3] = 1;'])
        """
        cp_declarations = [f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id};"]
        value = int(self.description[0], 16)
        bits = map(int, f"{value:0{self.output_bit_size}b}")
        cp_constraints = [f"constraint {self.id}[{i}] = {bit};" for i, bit in enumerate(bits)]

        return cp_declarations, cp_constraints

    def cp_continuous_differential_propagation_constraints(self, model):
        """
        Return CP declarations and constraints for continuous differential propagation.

        INPUT:

        - ``model`` -- **model object**; a model instance (unused by this component)

        OUTPUT:

        - ``tuple`` -- pair ``(cp_declarations, cp_constraints)``

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.cp_continuous_differential_propagation_constraints(object())
            (['array[0..3] of var -1.0..1.0: constant_0_0;'], ['constraint constant_0_0[0] = -1.0;', 'constraint constant_0_0[1] = -1.0;', 'constraint constant_0_0[2] = -1.0;', 'constraint constant_0_0[3] = -1.0;'])
        """
        size = self.output_bit_size

        cp_declarations = [
            f"array[0..{size - 1}] of var -1.0..1.0: {self.id};"
        ]

        cp_constraints = [
            f"constraint {self.id}[{i}] = -1.0;"
            for i in range(size)
        ]

        return cp_declarations, cp_constraints
    
    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_xor_differential_propagation_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.cp_xor_differential_propagation_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for CONSTANT component for CP wordwise deterministic truncated xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: DummyModel = type("DummyModel", (), {"word_size": 4})
            sage: constant_component = Constant(0, 18, 4, 0x1)
            sage: constant_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())
            (['array[0..0] of var 0..1: constant_0_18_active = array1d(0..0, [0]);', 'array[0..0] of var 0..1: constant_0_18_value = array1d(0..0, [0]);'], [])
        """
        output_bit_size = self.output_bit_size
        word_size = model.word_size
        new_declaration = (
            f"array[0..{(output_bit_size - 1) // word_size}] of var 0..1: "
            f"{self.id}_active = array1d(0..{(output_bit_size - 1) // word_size}, ["
            + ",".join("0" * (output_bit_size // word_size))
            + "]);"
        )
        cp_declarations = [new_declaration]
        cp_declarations.append(
            f"array[0..{(output_bit_size - 1) // word_size}] of var 0..1: "
            f"{self.id}_value = array1d(0..{(output_bit_size - 1) // word_size}, ["
            + ",".join("0" * (output_bit_size // word_size))
            + "]);"
        )
        cp_constraints = []

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for CONSTANT component for CP xor differential first step.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: DummyModel = type("DummyModel", (), {"word_size": 4})
            sage: constant_component = Constant(0, 30, 4, 0x0)
            sage: constant_component.cp_xor_differential_propagation_first_step_constraints(DummyModel())
            (['array[0..0] of var 0..1: constant_0_30 = array1d(0..0, [0]);'], [])
        """
        cp_declarations = [
            f"array[0..{(self.output_bit_size - 1) // model.word_size}] of var 0..1: "
            f"{self.id} = array1d(0..{(self.output_bit_size - 1) // model.word_size}, ["
            + ",".join("0" * (self.output_bit_size // model.word_size))
            + "]);"
        ]
        cp_constraints = []

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for CONSTANT component for CP xor differential model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.cp_xor_differential_propagation_constraints()
            (['array[0..3] of var 0..2: constant_0_0;'], ['constraint constant_0_0[0] = 0;', 'constraint constant_0_0[1] = 0;', 'constraint constant_0_0[2] = 0;', 'constraint constant_0_0[3] = 0;'])
        """
        cp_declarations = [f"array[0..{self.output_bit_size - 1}] of var 0..2: {self.id};"]
        cp_constraints = [f"constraint {self.id}[{i}] = 0;" for i in range(self.output_bit_size)]

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for CONSTANT component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..3] of var 0..1: constant_0_0_o;'], [])
        """
        cp_declarations = [f"array[0..{self.output_bit_size - 1}] of var 0..1: {self.id}_o;"]
        cp_constraints = []

        return cp_declarations, cp_constraints

    def get_bit_based_c_code(self, verbosity):
        """
        Return C code lines that initialize this constant as a bitstring.

        INPUT:

        - ``verbosity`` -- **boolean**; when ``True`` include debug print lines

        OUTPUT:

        - ``list`` -- C code lines

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 8, 0x1f)
            sage: constant_component.get_bit_based_c_code(False)
            ['\tBitString *constant_0_0 = bitstring_from_hex_string("0x1f", 8);']
        """
        constant_code = [
            f'\tBitString *{self.id} = bitstring_from_hex_string("'
            f'{int(self.description[0], 16):#0{(self.output_bit_size // 4) + 2}x}", '
            f"{self.output_bit_size});"
        ]

        if verbosity:
            constant_code.append(f'\tprintf("{self.id} input: 0x0");')
            constant_code.append(f'\tprintf("{self.id} output: ");')
            constant_code.append(f"\tprint_bitstring({self.id}, 16);\n")

        return constant_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Return vectorized Python code for the bit-based constant representation.

        INPUT:

        - ``params`` -- **list**; evaluation parameters (unused by this component)
        - ``convert_output_to_bytes`` -- **boolean**; output conversion flag (unused)

        OUTPUT:

        - ``list`` -- Python code lines

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x9)
            sage: constant_component.get_bit_based_vectorized_python_code([], False)
            ['  constant_0_0 = np.array([1, 0, 0, 1], dtype=np.uint8).reshape(4, 1)']
        """
        value = int(self.description[0], 0)
        bits = list(map(int, f"{value:0{self.output_bit_size}b}"))
        return [f"  {self.id} = np.array({bits}, dtype=np.uint8).reshape({self.output_bit_size}, 1)"]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Return vectorized Python code for the byte-based constant representation.

        INPUT:

        - ``params`` -- **list**; evaluation parameters (unused by this component)

        OUTPUT:

        - ``list`` -- Python code lines

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 12, 0x1000)
            sage: constant_component.get_byte_based_vectorized_python_code([])
            ['  constant_0_0 = np.array([1, 0], dtype=np.uint8).reshape(2, 1)']
        """
        val = constant_to_repr(self.description[0], self.output_bit_size)
        return [f"  {self.id} = np.array({val}, dtype=np.uint8).reshape({len(val)}, 1)"]

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        """
        Return C code lines that initialize this constant as a wordstring.

        INPUT:

        - ``verbosity`` -- **boolean**; when ``True`` include debug print lines
        - ``word_size`` -- **integer**; word size in bits
        - ``wordstring_variables`` -- **list**; accumulator list of generated wordstring variable names

        OUTPUT:

        - ``list`` -- C code lines

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 8, 0x1f)
            sage: vars_list = []
            sage: constant_component.get_word_based_c_code(False, 4, vars_list)
            ['\tWordString *constant_0_0 = wordstring_from_hex_string("0x1f", 2);']
            sage: vars_list
            ['constant_0_0']
        """
        constant_code = [
            f'\tWordString *{self.id} = wordstring_from_hex_string("'
            f'{int(self.description[0], 16):#0{(self.output_bit_size // 4) + 2}x}", '
            f"{self.output_bit_size // word_size});"
        ]
        wordstring_variables.append(self.id)
        if verbosity:
            constant_code.append(f'\tprintf("{self.id} input: 0x0\\n");')
            constant_code.append(f'\tprintf("{self.id} output: ");')
            constant_code.append(f"\tprint_wordstring({self.id}, 16);\n")

        return constant_code

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints modeling a component of type Constant for wordwise models.

        EXAMPLE::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = ConstantCipher(output_bit_size=4, value=0x1)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = cipher.component_from_id('constant_0_0')
            sage: variables, constraints = constant_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[constant_0_0_word_0_class]', x_0)]
            sage: constraints
            [x_0 == 0]

        """
        x_class = model.trunc_wordvar

        input_vars, output_vars = self._get_wordwise_input_output_linked_class(model)
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = [x_class[output_var] == 0 for output_var in output_vars]

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints modeling a component of type Constant.

        EXAMPLE::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = ConstantCipher(output_bit_size=4, value=0x1)
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = cipher.component_from_id('constant_0_0')
            sage: variables, constraints = constant_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[constant_0_0_0]', x_0), ('x_class[constant_0_0_1]', x_1), ('x_class[constant_0_0_2]', x_2), ('x_class[constant_0_0_3]', x_3)]
            sage: constraints
            [x_0 == 0, x_1 == 0, x_2 == 0, x_3 == 0]

        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = [x_class[output_var] == 0 for output_var in output_vars]

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return lists of variables and constrains modeling a component of type CONSTANT for MILP xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = ConstantCipher(output_bit_size=4, value=0x1)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = cipher.component_from_id('constant_0_0')
            sage: variables, constraints = constant_component.milp_xor_differential_propagation_constraints(milp)
            sage: variables
            [('x[constant_0_0_0]', x_0), ('x[constant_0_0_1]', x_1), ('x[constant_0_0_2]', x_2), ('x[constant_0_0_3]', x_3)]
            sage: constraints
            [x_0 == 0, x_1 == 0, x_2 == 0, x_3 == 0]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = [x[output_var] == 0 for output_var in output_vars]

        return variables, constraints

    def milp_wordwise_branch_number_number_of_active_sboxes_constraints(self, model):
        w = model._word_variable
        output_ids = self._milp_wordwise_branch_number_active_sboxes_output_ids(model)

        return [w[output_id] == 0 for output_id in output_ids]

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for CONSTANT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = ConstantCipher(output_bit_size=4, value=0x1)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = cipher.component_from_id('constant_0_0')
            sage: variables, constraints = constant_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[constant_0_0_0_o]', x_0), ('x[constant_0_0_1_o]', x_1), ('x[constant_0_0_2_o]', x_2), ('x[constant_0_0_3_o]', x_3)]
            sage: constraints
            []
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []

        return variables, constraints

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_xor_differential_propagation_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        """
        Return variables and constraints for the CONSTANT component for MINIZINC xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import MznXorDifferentialModelARXOptimized
            sage: cipher = ConstantCipher(output_bit_size=4, value=0x1)
            sage: minizinc = MznXorDifferentialModelARXOptimized(cipher)
            sage: constant_component = cipher.component_from_id('constant_0_0')
            sage: _, constant_xor_differential_constraints = constant_component.minizinc_xor_differential_propagation_constraints(minizinc)
            sage: constant_xor_differential_constraints[0]
            'constraint constant_0_0_y0 = 0;'
        """
        var_names = self.minizinc_define_var(model.input_postfix, model.output_postfix, model.data_type)
        constant_component_string = []
        constant_str_values = [f"{self.id}_{model.output_postfix}{i}" for i in range(self.output_bit_size)]
        for constant_str in constant_str_values:
            constant_component_string.append(f"constraint {constant_str} = 0;")

        return var_names, constant_component_string

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing CONSTANT for SAT CIPHER model

        The list of the constraints is just the binary representation of the value of the constant.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.sat_constraints()
            (['constant_0_0_0', 'constant_0_0_1', 'constant_0_0_2', 'constant_0_0_3'], ['-constant_0_0_0', '-constant_0_0_1', '-constant_0_0_2', 'constant_0_0_3'])
        """
        _, output_bit_ids = self._generate_output_ids()
        value = int(self.description[0], 16)
        bits = map(int, f"{value:0{self.output_bit_size}b}")
        signs = ["-" * (bit ^ 1) for bit in bits]
        constraints = [f"{sign}{output_bit_id}" for sign, output_bit_id in zip(signs, output_bit_ids)]

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing CONSTANT for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        The list of the constraints is just the binary representation of the value of the constant.
        Note that encoding symbols for deterministic truncated XOR differential model
        requires two variables per each symbol.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['constant_0_0_0_0', 'constant_0_0_1_0', 'constant_0_0_2_0', 'constant_0_0_3_0', 'constant_0_0_0_1', 'constant_0_0_1_1', 'constant_0_0_2_1', 'constant_0_0_3_1'], ['-constant_0_0_0_0', '-constant_0_0_1_0', '-constant_0_0_2_0', '-constant_0_0_3_0', '-constant_0_0_0_1', '-constant_0_0_1_1', '-constant_0_0_2_1', '-constant_0_0_3_1'])
        """
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        constraints = [f"-{out_id}" for out_id in out_ids_0] + [f"-{out_id}" for out_id in out_ids_1]

        return out_ids_0 + out_ids_1, constraints

    def sat_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing CONSTANT for SAT XOR DIFFERENTIAL model

        The value encoded is always zero for any constant since its contribute to the difference is null.

        .. SEEALSO::

            :ref:`sat-standard`

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.sat_xor_differential_propagation_constraints()
            (['constant_0_0_0', 'constant_0_0_1', 'constant_0_0_2', 'constant_0_0_3'], ['-constant_0_0_0', '-constant_0_0_1', '-constant_0_0_2', '-constant_0_0_3'])
        """
        _, output_bit_ids = self._generate_output_ids()
        constraints = [f"-{output_bit_id}" for output_bit_id in output_bit_ids]

        return output_bit_ids, constraints

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing CONSTANT for SAT XOR LINEAR model

        The list of the clauses is empty since in XOR linear analysis any constant flip the sign if needed.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.sat_xor_linear_mask_propagation_constraints()
            (['constant_0_0_0_o', 'constant_0_0_1_o', 'constant_0_0_2_o', 'constant_0_0_3_o'], [])
        """
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)

        return output_bit_ids, []

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing CONSTANT for SMT CIPHER model

        The list of the constraints is just the binary representation of the value of the constant.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.smt_constraints()
            (['constant_0_0_0', 'constant_0_0_1', 'constant_0_0_2', 'constant_0_0_3'], ['(assert (not constant_0_0_0))', '(assert (not constant_0_0_1))', '(assert (not constant_0_0_2))', '(assert constant_0_0_3)'])
        """
        _, output_bit_ids = self._generate_output_ids()
        value = int(self.description[0], 16)
        bits = map(int, f"{value:0{self.output_bit_size}b}")
        constraints = [
            smt_utils.smt_assert(output_bit_id) if bit else smt_utils.smt_assert(smt_utils.smt_not(output_bit_id))
            for bit, output_bit_id in zip(bits, output_bit_ids)
        ]

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing CONSTANT for SMT XOR DIFFERENTIAL model

        The value encoded is always zero for any constant since its contribute to the difference is null.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.smt_xor_differential_propagation_constraints()
            (['constant_0_0_0', 'constant_0_0_1', 'constant_0_0_2', 'constant_0_0_3'], ['(assert (not constant_0_0_0))', '(assert (not constant_0_0_1))', '(assert (not constant_0_0_2))', '(assert (not constant_0_0_3))'])
        """
        _, output_bit_ids = self._generate_output_ids()
        constraints = [smt_utils.smt_assert(smt_utils.smt_not(output_bit_id)) for output_bit_id in output_bit_ids]

        return output_bit_ids, constraints

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing CONSTANT for SMT XOR LINEAR model

        The list of the clauses is empty since in XOR linear analysis any constant flip the sign if needed.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.components.constant_component import Constant
            sage: constant_component = Constant(0, 0, 4, 0x1)
            sage: constant_component.smt_xor_linear_mask_propagation_constraints()
            (['constant_0_0_0_o', 'constant_0_0_1_o', 'constant_0_0_2_o', 'constant_0_0_3_o'], [])
        """
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(out_suffix)

        return output_bit_ids, []
