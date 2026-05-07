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
from claasp.cipher_modules.models.sat.utils import utils as sat_utils
from claasp.name_mappings import PERMUTATION_COMPONENT


class Permutation(Component):
    """
    Construct a permutation component.

    A permutation component that models a (word-wise or bitwise) permutation as simple bit
    equalities. The permutation description follows the CLAASP convention where
    each entry gives the destination position of the corresponding source word/bit.

    For ``word_size=1`` this means ``output[permutation_description[i]] = input[i]``.

    When ``word_size=1`` (default), this is a plain bitwise permutation where each entry in
    ``permutation_description`` is a source *bit* index.  When ``word_size > 1``, each entry is
    a source *word* index and the description has ``output_bit_size // word_size`` elements.

    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits.
    - ``permutation_description`` -- **list**; permutation mapping. When ``word_size=1``, each entry is
      a source bit index. When ``word_size > 1``, each entry is a source word index and the list has
      ``output_bit_size // word_size`` entries.
    - ``word_size`` -- **integer** (default: ``1``); number of bits per word. Set to ``1`` for bitwise
      permutation.

    EXAMPLES::

        sage: from claasp.components.permutation_component import Permutation
        sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
        sage: print(component.id)
        permutation_0_0
        sage: print(component.type)
        permutation
        sage: print(component.description)
        [[1, 3, 2, 0], 1]

    Word-wise example (two 4-bit words, swap them)::

        sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)
        sage: print(component.description)
        [[1, 0], 4]
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        permutation_description,
        word_size=1,
    ):
        component_id = f"permutation_{current_round_number}_{current_round_number_of_components}"
        component_type = PERMUTATION_COMPONENT
        input_len = sum(len(bits) for bits in input_bit_positions)
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(
            component_id,
            component_type,
            component_input,
            output_bit_size,
            [permutation_description, word_size],
        )

    def _bit_perm(self):
        """
        Return the bit-level permutation list.

        Expands the (possibly word-level) permutation stored in ``description`` to a flat list
        of input-bit indices for each output bit index.
        """
        perm = self.description[0]
        w = self.description[1]
        src_to_dst = [perm[j // w] * w + (j % w) for j in range(self.output_bit_size)]
        dst_to_src = [0] * self.output_bit_size
        for src, dst in enumerate(src_to_dst):
            dst_to_src[dst] = src

        return dst_to_src

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for PERMUTATION.

        The output is modeled as a simple equality: ``y[i] = x[bit_perm[i]]``

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: algebraic = AlgebraicModel(cipher)
            sage: permutation_component.algebraic_polynomials(algebraic)
            [permutation_0_0_y0 + permutation_0_0_x3,
             permutation_0_0_y1 + permutation_0_0_x0,
             permutation_0_0_y2 + permutation_0_0_x2,
             permutation_0_0_y3 + permutation_0_0_x1]
        """
        noutputs = self.output_bit_size
        ninputs = self.input_bit_size
        ring_r = model.ring()
        x = list(map(ring_r, [f"{self.id}_{model.input_postfix}{i}" for i in range(ninputs)]))
        y = list(map(ring_r, [f"{self.id}_{model.output_postfix}{i}" for i in range(noutputs)]))
        bit_perm = self._bit_perm()
        return [y[i] + x[bit_perm[i]] for i in range(noutputs)]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses for PERMUTATION in SAT CIPHER model.

        The output is constrained with simple equalities using CNF: ``y[i] <-> x[bit_perm[i]]``

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
            ['permutation_0_0_0 -input_3', 'input_3 -permutation_0_0_0',
             'permutation_0_0_1 -input_0', 'input_0 -permutation_0_0_1',
             'permutation_0_0_2 -input_2', 'input_2 -permutation_0_0_2',
             'permutation_0_0_3 -input_1', 'input_1 -permutation_0_0_3']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        bit_perm = self._bit_perm()
        input_bit_ids_permuted = [input_bit_ids[bit_perm[i]] for i in range(output_bit_len)]
        constraints = []
        for i in range(output_bit_len):
            constraints.extend(sat_utils.cnf_equivalent([output_bit_ids[i], input_bit_ids_permuted[i]]))

        return output_bit_ids, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_constraints()

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing PERMUTATION for SMT CIPHER model.

        The output is constrained with simple equalities: ``y[i] = x[bit_perm[i]]``

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: permutation_component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: output_bit_ids, constraints = permutation_component.smt_constraints()
            sage: output_bit_ids
            ['permutation_0_0_0', 'permutation_0_0_1', 'permutation_0_0_2', 'permutation_0_0_3']
            sage: constraints
            ['(assert (= permutation_0_0_0 input_3))',
             '(assert (= permutation_0_0_1 input_0))',
             '(assert (= permutation_0_0_2 input_2))',
             '(assert (= permutation_0_0_3 input_1))']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_len, output_bit_ids = self._generate_output_ids()
        bit_perm = self._bit_perm()
        input_bit_ids_permuted = [input_bit_ids[bit_perm[i]] for i in range(output_bit_len)]
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
            ['constraint permutation_0_0[0] = input[3];',
             'constraint permutation_0_0[1] = input[0];',
             'constraint permutation_0_0[2] = input[2];',
             'constraint permutation_0_0[3] = input[1];']
        """
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])

        bit_perm = self._bit_perm()
        cp_declarations = []
        cp_constraints = [
            f"constraint {self.id}[{i}] = {all_inputs[bit_perm[i]]};"
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
            [x_4 == x_3, x_5 == x_0, x_6 == x_2, x_7 == x_1]
        """
        x = model.binary_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        bit_perm = self._bit_perm()
        input_vars_permuted = [input_vars[bit_perm[i]] for i in range(len(output_vars))]
        constraints = [x[output_var] == x[input_var]
                       for output_var, input_var in zip(output_vars, input_vars_permuted)]

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def milp_xor_linear_mask_propagation_constraints(self, model):
        return self.milp_constraints(model)

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Return a list of strings for Python code that evaluates the PERMUTATION component.

        INPUT:

        - ``params`` -- **list**; list of bit vectors representing input parameters
        - ``convert_output_to_bytes`` -- **boolean**; whether to convert output to bytes

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: params = ['component_input']
            sage: permutation_component.get_bit_based_vectorized_python_code(params, False)
            ['  permutation_0_0 = bit_vector_permutation([component_input ], [1, 3, 2, 0], 1)']
        """
        perm = self.description[0]
        word_size = self.description[1]
        return [f"  {self.id} = bit_vector_permutation([{','.join(params)} ], {perm}, {word_size})"]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Return a list of strings for Python code that evaluates the PERMUTATION component using byte vectors.

        INPUT:

        - ``params`` -- **list**; list of byte vectors representing input parameters

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: permutation_component = cipher.component_from_id('permutation_0_0')
            sage: params = ['component_input']
            sage: permutation_component.get_byte_based_vectorized_python_code(params)
            ["  permutation_0_0 = byte_vector_permutation(['component_input'], [1, 3, 2, 0], 1, 4)"]
        """
        perm = self.description[0]
        word_size = self.description[1]
        return [f"  {self.id} = byte_vector_permutation({params}, {perm}, {word_size}, {self.input_bit_size})"]
