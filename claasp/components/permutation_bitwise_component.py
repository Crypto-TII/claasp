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
from claasp.name_mappings import PERMUTATION_COMPONENT


class PermutationBitwise(Component):
    """
    Construct a permutation component.

    A permutation component that models a bit permutation as simple bit equalities
    (output[i] = input[permutation_description[i]]).

    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``permutation_description`` -- **list**; permutation mapping where output[i] = input[permutation_description[i]].

    EXAMPLES::

        sage: from claasp.components.permutation_component import Permutation
        sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
        sage: print(component.id)
        permutation_0_0
        sage: print(component.type)
        permutation
        sage: print(component.description)
        [1, 3, 2, 0]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        permutation_description,
    ):
        component_id = f"permutation_{current_round_number}_{current_round_number_of_components}"
        component_type = PERMUTATION_COMPONENT
        input_len = 0
        for bits in input_bit_positions:
            input_len = input_len + len(bits)
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(
            component_id,
            component_type,
            component_input,
            output_bit_size,
            permutation_description,
        )

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for PERMUTATION.

        The output is modeled as a simple equality: y[i] = x[perm[i]]

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = PermutationCipher(bit_size=4, permutation=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: algebraic = AlgebraicModel(cipher)
            sage: permutation_component.algebraic_polynomials(algebraic)
            [permutation_0_0_y0 + permutation_0_0_x1,
             permutation_0_0_y1 + permutation_0_0_x3,
             permutation_0_0_y2 + permutation_0_0_x2,
             permutation_0_0_y3 + permutation_0_0_x0]
        """
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_R = model.ring()
        x = list(map(ring_R, [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]))
        y = list(map(ring_R, [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]))

        polynomials = [y[i] + x[self.description[i]] for i in range(noutputs)]

        return polynomials

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for PERMUTATION in SAT CIPHER model.

        The output is constrained with simple equalities using CNF: y[i] <-> x[perm[i]]

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: permutation_component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: output_bit_ids, constraints = permutation_component.sat_constraints()
            sage: output_bit_ids
            ['permutation_0_0_0', 'permutation_0_0_1', 'permutation_0_0_2', 'permutation_0_0_3']
            sage: constraints
            ['-permutation_0_0_0 input_1', 'permutation_0_0_0 -input_1',
             '-permutation_0_0_1 input_3', 'permutation_0_0_1 -input_3',
             '-permutation_0_0_2 input_2', 'permutation_0_0_2 -input_2',
             '-permutation_0_0_3 input_0', 'permutation_0_0_3 -input_0']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        
        input_bit_ids_permuted = [input_bit_ids[self.description[i]] for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids_permuted[i]]))

        return output_bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing PERMUTATION for SMT CIPHER model.

        The output is constrained with simple equalities: y[i] = x[perm[i]]

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: permutation_component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: output_bit_ids, constraints = permutation_component.smt_constraints()
            sage: output_bit_ids
            ['permutation_0_0_0', 'permutation_0_0_1', 'permutation_0_0_2', 'permutation_0_0_3']
            sage: constraints
            ['(assert (= permutation_0_0_0 input_1))',
             '(assert (= permutation_0_0_1 input_3))',
             '(assert (= permutation_0_0_2 input_2))',
             '(assert (= permutation_0_0_3 input_0))']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        
        input_bit_ids_permuted = [input_bit_ids[self.description[i]] for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids_permuted[i]])
            constraints.append(smt_utils.smt_assert(equation))

        return output_bit_ids, constraints

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for PERMUTATION component for CP CIPHER model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: permutation_component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: declarations, constraints = permutation_component.cp_constraints()
            sage: declarations
            []
            sage: constraints
            ['constraint permutation_0_0[0] = input[1];',
             'constraint permutation_0_0[1] = input[3];',
             'constraint permutation_0_0[2] = input[2];',
             'constraint permutation_0_0[3] = input[0];']
        """
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])

        cp_declarations = []
        cp_constraints = [
            f"constraint {self.id}[{i}] = {all_inputs[self.description[i]]};"
            for i in range(self.output_bit_size)
        ]

        return cp_declarations, cp_constraints

    def milp_constraints(self, model):
        """
        Return a list of variables and a list of MILP constraints for PERMUTATION.

        The permutation is modeled with simple variable equality constraints.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = permutation_component.milp_constraints(milp)
            sage: variables
            [('x[plaintext_0]', x_0),
            ('x[plaintext_1]', x_1),
            ('x[plaintext_2]', x_2),
            ('x[plaintext_3]', x_3),
            ('x[permutation_0_0_0]', x_4),
            ('x[permutation_0_0_1]', x_5),
            ('x[permutation_0_0_2]', x_6),
            ('x[permutation_0_0_3]', x_7)]
            sage: constraints
            [x_4 == x_1, x_5 == x_3, x_6 == x_2, x_7 == x_0]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []

        # Create permutation mapping: output[i] = input[permutation[i]]
        input_vars_permuted = [input_vars[self.description[i]] for i in range(len(output_vars))]
        for output_var, input_var in zip(output_vars, input_vars_permuted):
            constraints.append(x[output_var] == x[input_var])

        return variables, constraints

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Return a list of strings for Python code that evaluates the PERMUTATION component.

        The permutation is implemented using vectorized bit operations.

        INPUT:

        - ``params`` -- **list**; list of bit vectors representing input parameters
        - ``convert_output_to_bytes`` -- **boolean**; whether to convert output to bytes

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: params = ['component_input']
            sage: permutation_component.get_bit_based_vectorized_python_code(params, False)
            ['  permutation_0_0 = bit_vector_permutation([component_input ], [1, 3, 2, 0])']
        """
        return [f"  {self.id} = bit_vector_permutation([{','.join(params)} ], {self.description})"]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Return a list of strings for Python code that evaluates the PERMUTATION component using byte vectors.

        The permutation is implemented using vectorized byte operations.

        INPUT:

        - ``params`` -- **list**; list of byte vectors representing input parameters

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: params = ['component_input']
            sage: permutation_component.get_byte_based_vectorized_python_code(params)
            ['  permutation_0_0 = byte_vector_permutation(component_input, [1, 3, 2, 0], 4)']
        """
        return [f"  {self.id} = byte_vector_permutation({params}, {self.description}, {self.input_bit_size})"]

