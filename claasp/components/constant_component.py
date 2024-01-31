
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
from claasp.cipher_modules.models.sat.utils import constants
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.cipher_modules.code_generator import constant_to_bitstring


def constant_to_repr(val, output_size):
    _val = int(val, 0)
    if output_size % 8 != 0:
        s = output_size + (8 - (output_size % 8))
    else:
        s = output_size
    ret = [(_val >> s - (8 * (i + 1))) & 0xff for i in range(s // 8)]

    return ret


class Constant(Component):

    def __init__(self, current_round_number, current_round_number_of_components,
                 output_bit_size, value):
        component_id = f'constant_{current_round_number}_{current_round_number_of_components}'
        component_type = 'constant'
        if output_bit_size % 4 == 0:
            description = [f"{value:#0{(output_bit_size // 4) + 2}x}"]
        else:
            description = [f"{value:#0{output_bit_size + 2}b}"]
        component_input = Input(0, [''], [[]])
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for CONSTANT addition.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: constant_component = fancy.get_component_from_id("constant_0_10")
            sage: algebraic = AlgebraicModel(fancy)
            sage: constant_component.algebraic_polynomials(algebraic)
            [constant_0_10_y0,
             constant_0_10_y1 + 1,
             constant_0_10_y2,
             constant_0_10_y3 + 1,
             constant_0_10_y4 + 1,
             constant_0_10_y5 + 1,
             constant_0_10_y6,
             constant_0_10_y7 + 1,
             constant_0_10_y8,
             constant_0_10_y9,
             constant_0_10_y10 + 1,
             constant_0_10_y11 + 1,
             constant_0_10_y12 + 1,
             constant_0_10_y13,
             constant_0_10_y14 + 1,
             constant_0_10_y15 + 1,
             constant_0_10_y16,
             constant_0_10_y17 + 1,
             constant_0_10_y18 + 1,
             constant_0_10_y19 + 1,
             constant_0_10_y20 + 1,
             constant_0_10_y21 + 1,
             constant_0_10_y22 + 1,
             constant_0_10_y23 + 1]
        """
        noutputs = self.output_bit_size
        constant = int(self.description[0], 16)

        ring_R = model.ring()
        y = list(map(ring_R, [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]))

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

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.cms_constraints()
            (['constant_2_0_0',
              'constant_2_0_1',
              'constant_2_0_2',
              ...
              '-constant_2_0_13',
              '-constant_2_0_14',
              'constant_2_0_15'])
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

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.cp_constraints()
            (['array[0..15] of var 0..1: constant_2_0 = array1d(0..15, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);'],
             [])
        """
        output_size = self.output_bit_size
        output_id_link = self.id
        description = self.description
        value = f'{int(description[0], 16):0{output_size}b}'
        new_declaration = f'array[0..{int(output_size) - 1}] of var 0..1: {output_id_link};'
        cp_declarations = [new_declaration]
        cp_constraints = []
        for i in range(output_size):
            cp_constraints.append(f'constraint {output_id_link}[{i}] = 0;')

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.cp_xor_differential_propagation_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for CONSTANT component for CP wordwise deterministic truncated xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: from claasp.components.constant_component import Constant
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: constant_component = Constant(0, 18, 16, 0xAB01)
            sage: constant_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)
            (['array[0..1] of var 0..1: constant_0_18_active = array1d(0..1, [0,0]);',
              'array[0..1] of var 0..1: constant_0_18_value = array1d(0..1, [0,0]);'],
             [])
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        word_size = model.word_size
        new_declaration = f'array[0..{(output_size - 1) // word_size}] of var 0..1: ' \
                          f'{output_id_link}_active = array1d(0..{(output_size - 1) // word_size}, [' \
                          + ','.join('0' * (output_size // word_size)) + ']);'
        cp_declarations = [new_declaration]
        cp_declarations.append(f'array[0..{(output_size - 1) // word_size}] of var 0..1: '
                               f'{output_id_link}_value = array1d(0..{(output_size - 1) // word_size}, ['
                               + ','.join('0' * (output_size // word_size)) + ']);')
        cp_constraints = []

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for CONSTANT component for CP xor differential first step.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.cp_model import CpModel
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: cp = CpModel(aes)
            sage: constant_component = aes.component_from(0, 30)
            sage: constant_component.cp_xor_differential_propagation_first_step_constraints(cp)
            (['array[0..3] of var 0..1: constant_0_30 = array1d(0..3, [0,0,0,0]);'], [])
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        new_declaration = f'array[0..{(output_size - 1) // model.word_size}] of var 0..1: ' \
                          f'{output_id_link} = array1d(0..{(output_size - 1) // model.word_size}, [' \
                          + ','.join('0' * (output_size // model.word_size)) + ']);'
        cp_declarations = [new_declaration]
        cp_constraints = []
        result = cp_declarations, cp_constraints
        return result

    def cp_xor_differential_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for CONSTANT component for CP xor differential model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.cp_xor_differential_propagation_constraints()
            (['array[0..15] of var 0..1: constant_2_0 = array1d(0..15, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);'],
             [])
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        #new_declaration = f'array[0..{output_size - 1}] of var 0..1: ' \
        #                  f'{output_id_link} = array1d(0..{output_size - 1}, [' \
        #                  + ','.join('0' * output_size) + ']);'
        #cp_declarations = [new_declaration]
        #cp_constraints = []
        new_declaration = f'array[0..{int(output_size) - 1}] of var 0..2: {output_id_link};'
        cp_declarations = [new_declaration]
        cp_constraints = []
        for i in range(output_size):
            cp_constraints.append(f'constraint {output_id_link}[{i}] = 0;')

        return cp_declarations, cp_constraints
        result = cp_declarations, cp_constraints
        return result

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return lists of declarations and constraints for CONSTANT component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.cp_xor_linear_mask_propagation_constraints()
            (['array[0..15] of var 0..1: constant_2_0_o;'],
             [])
        """
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        cp_declarations = []
        cp_constraints = []
        new_declaration = f'array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;'
        cp_declarations.append(new_declaration)
        result = cp_declarations, cp_constraints
        return result

    def get_bit_based_c_code(self, verbosity):
        constant_code = [f'\tBitString *{self.id} = bitstring_from_hex_string("'
                         f'{int(self.description[0], 16):#0{(self.output_bit_size // 4) + 2}x}", '
                         f'{self.output_bit_size});']

        if verbosity:
            constant_code.append(f'\tprintf("{self.id} input: 0x0");')
            constant_code.append(f'\tprintf("{self.id} output: ");')
            constant_code.append(f'\tprint_bitstring({self.id}, 16);\n')

        return constant_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        return [f'  {self.id} = np.array({constant_to_bitstring(self.description[0], self.output_bit_size)}, '
                f'dtype=np.uint8).reshape({self.output_bit_size, 1})']

    def get_byte_based_vectorized_python_code(self, params):
        val = constant_to_repr(self.description[0], self.output_bit_size)
        return [f'  {self.id} = np.array({val}, dtype=np.uint8).reshape({len(val)}, 1)']

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        constant_code = [f'\tWordString *{self.id} = wordstring_from_hex_string("'
                         f'{int(self.description[0], 16):#0{(self.output_bit_size // 4) + 2}x}", '
                         f'{self.output_bit_size // word_size});']
        wordstring_variables.append(self.id)
        if verbosity:
            constant_code.append(f'\tprintf("{self.id} input: 0x0\\n");')
            constant_code.append(f'\tprintf("{self.id} output: ");')
            constant_code.append(f'\tprint_wordstring({self.id}, 16);\n')

        return constant_code

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints modeling a component of type Constant for wordwise models.

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.components.constant_component import Constant
            sage: aes = AESBlockCipher(number_of_rounds=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = aes.get_component_from_id("constant_0_30")
            sage: variables, constraints = constant_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[constant_0_30_word_0_class]', x_0),
             ('x_class[constant_0_30_word_1_class]', x_1),
             ('x_class[constant_0_30_word_2_class]', x_2),
             ('x_class[constant_0_30_word_3_class]', x_3)]
            sage: constraints
            [x_0 == 0, x_1 == 0, x_2 == 0, x_3 == 0]

        """
        x_class = model.trunc_wordvar

        input_vars, output_vars = self._get_wordwise_input_output_linked_class(model)
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(len(output_vars)):
            constraints.append(x_class[output_vars[i]] == 0)
        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of variables and a list of constraints modeling a component of type Constant.

        EXAMPLE::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = speck.get_component_from_id("constant_1_0")
            sage: variables, constraints = constant_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[constant_1_0_0]', x_0),
            ('x_class[constant_1_0_1]', x_1),
            ...
            ('x_class[constant_1_0_14]', x_14),
            ('x_class[constant_1_0_15]', x_15)]
            sage: constraints
            [x_0 == 0,
            x_1 == 0,
            ...
            x_14 == 0,
            x_15 == 0]

        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]
        constraints = []
        for i in range(self.output_bit_size):
            constraints.append(x_class[output_vars[i]] == 0)
        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return lists of variables and constrains modeling a component of type CONSTANT for MILP xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = speck.get_component_from_id("constant_1_0")
            sage: variables, constraints = constant_component.milp_xor_differential_propagation_constraints(milp)
            sage: variables
            [('x[constant_1_0_0]', x_0),
            ('x[constant_1_0_1]', x_1),
            ...
            ('x[constant_1_0_14]', x_14),
            ('x[constant_1_0_15]', x_15)]
            sage: constraints
            [x_0 == 0,
            x_1 == 0,
            ...
            x_14 == 0,
            x_15 == 0]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = [x[output_vars[i]] == 0 for i in range(self.output_bit_size)]
        result = variables, constraints
        return result

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a list of variables and a list of constraints for CONSTANT component for MILP xor linear.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=3)
            sage: milp = MilpModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: constant_component = speck.get_component_from_id("constant_2_0")
            sage: variables, constraints = constant_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[constant_2_0_0_o]', x_0),
            ('x[constant_2_0_1_o]', x_1),
            ...
            ('x[constant_2_0_14_o]', x_14),
            ('x[constant_2_0_15_o]', x_15)]
            sage: constraints
            []
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        result = variables, constraints
        return result

    def minizinc_deterministic_truncated_xor_differential_trail_constraints(self, model):
        return self.minizinc_xor_differential_propagation_constraints(model)

    def minizinc_xor_differential_propagation_constraints(self, model):
        """
        Return variables and constraints for the CONSTANT component for MINIZINC xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: fancy = FancyBlockCipher(number_of_rounds=1)
            sage: minizinc = MinizincXorDifferentialModel(fancy)
            sage: constant_component = fancy.get_component_from_id("constant_0_10")
            sage: _, constant_xor_differential_constraints = constant_component.minizinc_xor_differential_propagation_constraints(minizinc)
            sage: constant_xor_differential_constraints[6]
            'constraint constant_0_10_y6=0;'
        """
        var_names = self._define_var(model.input_postfix, model.output_postfix, model.data_type)
        constant_component_string = []
        noutputs = self.output_bit_size
        constant_str_values = [self.id + "_" + model.output_postfix + str(i) for i in range(noutputs)]
        for constant_str in constant_str_values:
            constant_component_string.append(f'constraint {constant_str}=0;')
        result = var_names, constant_component_string
        return result

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for a CONSTANT in SAT CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.sat_constraints()
            (['constant_2_0_0',
              'constant_2_0_1',
              'constant_2_0_2',
              ...
              '-constant_2_0_13',
              '-constant_2_0_14',
              'constant_2_0_15'])
        """
        output_bit_len, output_bit_ids = self._generate_output_ids()
        value = int(self.description[0], 16)
        value_bits = [value >> i & 1 for i in reversed(range(output_bit_len))]
        minus = ['-' * (not i) for i in value_bits]
        constraints = [f'{minus[i]}{output_bit_ids[i]}' for i in range(output_bit_len)]

        return output_bit_ids, constraints

    def sat_deterministic_truncated_xor_differential_trail_constraints(self):
        return self.sat_xor_differential_propagation_constraints()

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return lists of variables and strings representing clauses for CONSTANT for SAT xor differential.

        .. SEEALSO::

            :ref:`sat-standard`

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.sat_xor_differential_propagation_constraints()
            (['constant_2_0_0',
              'constant_2_0_1',
              'constant_2_0_2',
              ...
              '-constant_2_0_13',
              '-constant_2_0_14',
              '-constant_2_0_15'])
        """
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = [f'-{output_bit_ids[i]}' for i in range(output_bit_len)]
        result = output_bit_ids, constraints
        return result

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses for a CONSTANT in SAT XOR LINEAR model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: constant_component = speck.component_from(2, 0)
            sage: constant_component.sat_xor_linear_mask_propagation_constraints()
            (['constant_2_0_0_o',
              'constant_2_0_1_o',
              'constant_2_0_2_o',
              ...
              'constant_2_0_14_o',
              'constant_2_0_15_o'],
             [])
        """
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        result = output_bit_ids, []
        return result

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing a CONSTANT SMT CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: constant_component = tea.component_from(0, 2)
            sage: constant_component.smt_constraints()
            (['constant_0_2_0',
              'constant_0_2_1',
              ...
              'constant_0_2_30',
              'constant_0_2_31'],
             ['(assert constant_0_2_0)',
              '(assert (not constant_0_2_1))',
              ...
              '(assert (not constant_0_2_30))',
              '(assert constant_0_2_31)'])
        """
        output_bit_len, output_bit_ids = self._generate_output_ids()
        value = int(self.description[0], 16)
        constraints = [smt_utils.smt_assert(output_bit_ids[i]) if value >> (output_bit_len - 1 - i) & 1
                       else smt_utils.smt_assert(smt_utils.smt_not(output_bit_ids[i]))
                       for i in range(output_bit_len)]

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing a CONSTANT for SMT xor differential.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: constant_component = tea.component_from(0, 2)
            sage: constant_component.smt_xor_differential_propagation_constraints()
            (['constant_0_2_0',
              'constant_0_2_1',
              ...
              'constant_0_2_30',
              'constant_0_2_31'],
             ['(assert (not constant_0_2_0))',
              '(assert (not constant_0_2_1))',
              ...
              '(assert (not constant_0_2_30))',
              '(assert (not constant_0_2_31))'])
        """
        output_bit_len, output_bit_ids = self._generate_output_ids()
        constraints = [smt_utils.smt_assert(smt_utils.smt_not(output_bit_ids[i]))
                       for i in range(output_bit_len)]
        result = output_bit_ids, constraints
        return result

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts for a CONSTANT in SMT XOR LINEAR model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); a model instance

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
            sage: tea = TeaBlockCipher(number_of_rounds=3)
            sage: constant_component = tea.component_from(0, 2)
            sage: constant_component.smt_xor_linear_mask_propagation_constraints()
            (['constant_0_2_0_o',
              'constant_0_2_1_o',
              ...
              'constant_0_2_30_o',
              'constant_0_2_31_o'],
             [])
        """
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        _, output_bit_ids = self._generate_output_ids(out_suffix)
        result = output_bit_ids, []
        return result
