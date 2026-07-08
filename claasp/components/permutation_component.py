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


from claasp.cipher_modules.models.sat.utils import constants, utils as sat_utils
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.component import Component
from claasp.input import Input
from claasp.name_mappings import PERMUTATION_COMPONENT
from claasp.utils.utils import coerce_exact_int


class Permutation(Component):
    """
    Construct a permutation component.

    A permutation component that models a (word-wise or bitwise) permutation as simple bit
    equalities. The permutation description follows the CLAASP convention where
    each entry gives the destination position of the corresponding source word/bit.

    For ``word_size=1`` this means ``output[permutation_description[i]] = input[i]``.

    When ``word_size=1`` (default), this is a plain bitwise permutation where each entry in
    ``permutation_description`` gives the destination of source bit ``i``. When ``word_size > 1``,
    each entry gives the destination of source word ``i`` and the description has
    ``output_bit_size // word_size`` elements.

    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits.
    - ``permutation_description`` -- **list**; permutation mapping from source position to destination
        position. When ``word_size=1``, ``permutation_description[i]`` is the destination bit index for
        source bit ``i``. When ``word_size > 1``, ``permutation_description[i]`` is the destination word
        index for source word ``i`` and the list has ``output_bit_size // word_size`` entries.
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
        # Validate word_size
        try:
            word_size = coerce_exact_int(word_size, "word_size")
        except ValueError as e:
            raise ValueError(str(e))

        if word_size <= 0:
            raise ValueError(f"word_size must be a positive integer, got {word_size}")

        # Validate that output_bit_size is divisible by word_size
        if output_bit_size % word_size != 0:
            raise ValueError(
                f"output_bit_size ({output_bit_size}) must be divisible by word_size ({word_size})"
            )

        # Validate permutation_description length
        expected_perm_len = output_bit_size // word_size
        if len(permutation_description) != expected_perm_len:
            raise ValueError(
                f"permutation_description length ({len(permutation_description)}) "
                f"does not match expected length ({expected_perm_len}) "
                f"for output_bit_size={output_bit_size} and word_size={word_size}"
            )

        # Validate that permutation_description is a valid permutation
        perm_set = set(permutation_description)
        valid_range = set(range(expected_perm_len))
        if perm_set != valid_range:
            missing = valid_range - perm_set
            duplicates = [x for x in permutation_description if permutation_description.count(x) > 1]
            out_of_range = [x for x in permutation_description if not isinstance(x, int) or x < 0 or x >= expected_perm_len]

            error_parts = []
            if out_of_range:
                error_parts.append(f"out-of-range values {set(out_of_range)}")
            if missing:
                error_parts.append(f"missing values {missing}")
            if duplicates:
                error_parts.append(f"duplicate values {set(duplicates)}")

            raise ValueError(
                f"permutation_description is not a valid permutation: {', '.join(error_parts)}. "
                f"All values must be unique integers in range [0, {expected_perm_len - 1}]"
            )

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

    def cms_constraints(self):
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model=None):
        return self.cms_constraints()

    def cms_xor_linear_mask_propagation_constraints(self, model=None):
        return self.cms_constraints()

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses for PERMUTATION in SAT bitwise deterministic
        truncated XOR differential model.

        A permutation copies each input bit to the corresponding output bit; the 2-bit truncated
        encoding is therefore preserved verbatim.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: variables, constraints = component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            sage: variables
            ['permutation_0_0_0_0',
             'permutation_0_0_1_0',
             'permutation_0_0_2_0',
             'permutation_0_0_3_0',
             'permutation_0_0_0_1',
             'permutation_0_0_1_1',
             'permutation_0_0_2_1',
             'permutation_0_0_3_1']
            sage: constraints
            ['permutation_0_0_0_0 -input_3_0',
             'input_3_0 -permutation_0_0_0_0',
             'permutation_0_0_0_1 -input_3_1',
             'input_3_1 -permutation_0_0_0_1',
             'permutation_0_0_1_0 -input_0_0',
             'input_0_0 -permutation_0_0_1_0',
             'permutation_0_0_1_1 -input_0_1',
             'input_0_1 -permutation_0_0_1_1',
             'permutation_0_0_2_0 -input_2_0',
             'input_2_0 -permutation_0_0_2_0',
             'permutation_0_0_2_1 -input_2_1',
             'input_2_1 -permutation_0_0_2_1',
             'permutation_0_0_3_0 -input_1_0',
             'input_1_0 -permutation_0_0_3_0',
             'permutation_0_0_3_1 -input_1_1',
             'input_1_1 -permutation_0_0_3_1']
        """
        in_ids_0, in_ids_1 = self._generate_input_double_ids()
        _, out_ids_0, out_ids_1 = self._generate_output_double_ids()
        bit_perm = self._bit_perm()
        constraints = []
        for i in range(len(out_ids_0)):
            constraints.extend(sat_utils.cnf_equivalent([out_ids_0[i], in_ids_0[bit_perm[i]]]))
            constraints.extend(sat_utils.cnf_equivalent([out_ids_1[i], in_ids_1[bit_perm[i]]]))

        return out_ids_0 + out_ids_1, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        return self.sat_constraints()

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        return self.sat_constraints()

    def sat_semi_deterministic_truncated_xor_differential_constraints(self):
        return self.sat_bitwise_deterministic_truncated_xor_differential_constraints()

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

    def smt_xor_differential_propagation_constraints(self, model):
        """
        Return a variable list and SMT-LIB list asserts representing PERMUTATION for SMT XOR DIFFERENTIAL model.

        Delegates to :meth:`smt_constraints` since permutation propagates differences as plain
        bit equalities.

        INPUT:

        - ``model`` -- **model object**; a model instance (unused, kept for API parity)

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: component.smt_xor_differential_propagation_constraints(None) == component.smt_constraints()
            True
        """
        return self.smt_constraints()

    def smt_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a variable list and SMT-LIB list asserts representing PERMUTATION for SMT XOR LINEAR model.

        For a permutation, linear mask propagation satisfies
        ``output_mask[i] = input_mask[bit_perm[i]]`` (the mask at output position ``i`` equals the
        mask at the source input position).  This uses component-local ``_i`` / ``_o`` variable names
        as expected by the SMT XOR linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); unused, kept for API parity

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: variables, constraints = component.smt_xor_linear_mask_propagation_constraints()
            sage: variables
            ['permutation_0_0_0_i',
             'permutation_0_0_1_i',
             'permutation_0_0_2_i',
             'permutation_0_0_3_i',
             'permutation_0_0_0_o',
             'permutation_0_0_1_o',
             'permutation_0_0_2_o',
             'permutation_0_0_3_o']
            sage: constraints
            ['(assert (= permutation_0_0_0_o permutation_0_0_3_i))',
             '(assert (= permutation_0_0_1_o permutation_0_0_0_i))',
             '(assert (= permutation_0_0_2_o permutation_0_0_2_i))',
             '(assert (= permutation_0_0_3_o permutation_0_0_1_i))']
        """
        input_bit_len, input_bit_ids = self._generate_component_input_ids()
        out_suffix = constants.OUTPUT_BIT_ID_SUFFIX
        output_bit_len, output_bit_ids = self._generate_output_ids(suffix=out_suffix)
        bit_perm = self._bit_perm()
        constraints = []
        for i in range(output_bit_len):
            equation = smt_utils.smt_equivalent([output_bit_ids[i], input_bit_ids[bit_perm[i]]])
            constraints.append(smt_utils.smt_assert(equation))

        return input_bit_ids + output_bit_ids, constraints

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

    def cp_deterministic_truncated_xor_differential_trail_constraints(self):
        """
        Return lists of declarations and constraints for PERMUTATION in CP deterministic truncated xor differential model.

        A permutation propagates differences deterministically: each output bit copies its
        corresponding input bit, so the truncated-model value (0, 1, or 2) is preserved.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: declarations, constraints = component.cp_deterministic_truncated_xor_differential_trail_constraints()
            sage: declarations
            []
            sage: constraints
            ['constraint if ((input[3] < 2)) then permutation_0_0[0] = (input[3]) mod 2 else permutation_0_0[0] = 2 endif;',
             'constraint if ((input[0] < 2)) then permutation_0_0[1] = (input[0]) mod 2 else permutation_0_0[1] = 2 endif;',
             'constraint if ((input[2] < 2)) then permutation_0_0[2] = (input[2]) mod 2 else permutation_0_0[2] = 2 endif;',
             'constraint if ((input[1] < 2)) then permutation_0_0[3] = (input[1]) mod 2 else permutation_0_0[3] = 2 endif;']
        """
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"{id_link}[{position}]" for position in bit_positions])

        bit_perm = self._bit_perm()
        cp_declarations = []
        cp_constraints = [
            f"constraint if (({all_inputs[bit_perm[i]]} < 2)) then "
            f"{self.id}[{i}] = ({all_inputs[bit_perm[i]]}) mod 2 "
            f"else {self.id}[{i}] = 2 endif;"
            for i in range(self.output_bit_size)
        ]
        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self):
        return self.cp_deterministic_truncated_xor_differential_trail_constraints()

    def cp_semi_deterministic_truncated_xor_differential_constraints(self):
        """
        Return lists of declarations and constraints for PERMUTATION in CP semi-deterministic
        truncated XOR differential model.

        Delegates to :meth:`cp_deterministic_truncated_xor_differential_trail_constraints`
        (same semantics as LinearLayer).

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: component.cp_semi_deterministic_truncated_xor_differential_constraints() == \
            ...       component.cp_deterministic_truncated_xor_differential_trail_constraints()
            True
        """
        return self.cp_deterministic_truncated_xor_differential_trail_constraints()

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for PERMUTATION in CP wordwise deterministic
        truncated XOR differential model.

        Each output word copies the active/value status of the corresponding input word according to
        the permutation.  The permutation must be word-aligned (all source bits of an output word
        must come from the same input word); otherwise a :exc:`ValueError` is raised.

        INPUT:

        - ``model`` -- **model object**; a model instance with a ``word_size`` attribute

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: DummyModel = type('DummyModel', (), {'word_size': 4})
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)
            sage: declarations, constraints = component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())
            sage: declarations
            []
            sage: constraints
            ['constraint if ((input_active[1] == 0)) then permutation_0_0_active[0] = 0 /\\ permutation_0_0_value[0] = 0 elsepermutation_0_0_active[0] = 3 /\\ permutation_0_0_value[0] = -2 endif;',
             'constraint if ((input_active[0] == 0)) then permutation_0_0_active[1] = 0 /\\ permutation_0_0_value[1] = 0 elsepermutation_0_0_active[1] = 3 /\\ permutation_0_0_value[1] = -2 endif;']
        """
        word_size = model.word_size
        output_num_words = self.output_bit_size // word_size

        all_inputs_active = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs_active.extend([
                f"{id_link}_active[{bit_positions[j * word_size] // word_size}]"
                for j in range(len(bit_positions) // word_size)
            ])

        bit_perm = self._bit_perm()
        cp_constraints = []
        for out_word_idx in range(output_num_words):
            output_bit_start = out_word_idx * word_size
            input_bit_indexes = [bit_perm[output_bit_start + k] for k in range(word_size)]
            input_word_idxs = {b // word_size for b in input_bit_indexes}
            if len(input_word_idxs) != 1:
                raise ValueError(
                    f"{self.id}: permutation mixes bits across model words "
                    f"(model.word_size={word_size}); unsupported in wordwise model"
                )
            in_word_idx = input_word_idxs.pop()
            input_active = all_inputs_active[in_word_idx]
            cp_constraint = (
                f"constraint if (({input_active} == 0)) then "
                f"{self.id}_active[{out_word_idx}] = 0 /\\ {self.id}_value[{out_word_idx}] = 0 else"
                f"{self.id}_active[{out_word_idx}] = 3 /\\ {self.id}_value[{out_word_idx}] = -2 endif;"
            )
            cp_constraints.append(cp_constraint)

        return [], cp_constraints

    def cp_xor_differential_propagation_constraints(self, model):
        # TODO: keep the model argument for API parity with LinearLayer;
        # remove this unused parameter in a later cleanup PR after harmonizing call sites.
        return self.cp_constraints()

    def cp_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return declarations and constraints for PERMUTATION in CP xor linear model.

        INPUT:

        - ``model`` -- **model object** (default: `None`); unused, kept for API compatibility

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: declarations, constraints = component.cp_xor_linear_mask_propagation_constraints()
            sage: declarations
            ['array[0..3] of var 0..1:permutation_0_0_i;', 'array[0..3] of var 0..1:permutation_0_0_o;']
            sage: constraints
            ['constraint permutation_0_0_o[0]=permutation_0_0_i[3];',
             'constraint permutation_0_0_o[1]=permutation_0_0_i[0];',
             'constraint permutation_0_0_o[2]=permutation_0_0_i[2];',
             'constraint permutation_0_0_o[3]=permutation_0_0_i[1];']
        """
        cp_declarations = [
            f"array[0..{self.input_bit_size - 1}] of var 0..1:{self.id}_i;",
            f"array[0..{self.output_bit_size - 1}] of var 0..1:{self.id}_o;",
        ]
        bit_perm = self._bit_perm()
        cp_constraints = [
            f"constraint {self.id}_o[{i}]={self.id}_i[{bit_perm[i]}];"
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

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return a list of MILP variables and constraints for PERMUTATION in the bitwise
        deterministic truncated XOR differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.permutation_component import Permutation
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3]], 4, [1, 3, 2, 0])
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[input_0]', x_0),
             ('x_class[input_1]', x_1),
             ('x_class[input_2]', x_2),
             ('x_class[input_3]', x_3),
             ('x_class[permutation_0_0_0]', x_4),
             ('x_class[permutation_0_0_1]', x_5),
             ('x_class[permutation_0_0_2]', x_6),
             ('x_class[permutation_0_0_3]', x_7)]
            sage: constraints
            [x_4 == x_3, x_5 == x_0, x_6 == x_2, x_7 == x_1]
        """
        x_class = model.trunc_binvar

        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_vars + output_vars]

        bit_perm = self._bit_perm()
        constraints = [
            x_class[output_var] == x_class[input_vars[bit_perm[i]]]
            for i, output_var in enumerate(output_vars)
        ]

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Returns a list of MILP variables and a list of constraints for PERMUTATION
        component in the wordwise deterministic truncated XOR differential model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::
            sage: from claasp.components.permutation_component import Permutation
            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: component = Permutation(0, 0, ['input'], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)
            sage: cipher = PermutationCipher(bit_size=8, permutation_description=[1, 0], word_size=4)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x[input_word_0_class_bit_0]', x_0),
             ('x[input_word_0_class_bit_1]', x_1),
             ('x[input_0]', x_2),
             ('x[input_1]', x_3),
             ('x[input_2]', x_4),
             ('x[input_3]', x_5),
             ('x[input_word_1_class_bit_0]', x_6),
             ('x[input_word_1_class_bit_1]', x_7),
             ('x[input_4]', x_8),
             ('x[input_5]', x_9),
             ('x[input_6]', x_10),
             ('x[input_7]', x_11),
             ('x[permutation_0_0_word_0_class_bit_0]', x_12),
             ('x[permutation_0_0_word_0_class_bit_1]', x_13),
             ('x[permutation_0_0_0]', x_14),
             ('x[permutation_0_0_1]', x_15),
             ('x[permutation_0_0_2]', x_16),
             ('x[permutation_0_0_3]', x_17),
             ('x[permutation_0_0_word_1_class_bit_0]', x_18),
             ('x[permutation_0_0_word_1_class_bit_1]', x_19),
             ('x[permutation_0_0_4]', x_20),
             ('x[permutation_0_0_5]', x_21),
             ('x[permutation_0_0_6]', x_22),
             ('x[permutation_0_0_7]', x_23)]
            sage: constraints
            [x_12 == x_6,
             x_13 == x_7,
             x_14 == x_8,
             x_15 == x_9,
             x_16 == x_10,
             x_17 == x_11,
             x_18 == x_0,
             x_19 == x_1,
             x_20 == x_2,
             x_21 == x_3,
             x_22 == x_4,
             x_23 == x_5]
        """
        x = model.binary_variable
        model_word_size = model.word_size

        if self.input_bit_size % model_word_size != 0 or self.output_bit_size % model_word_size != 0:
            raise ValueError(
                f"{self.id}: input/output size must be divisible by model.word_size={model_word_size}"
            )

        input_tuples, output_tuples = self._get_wordwise_input_output_full_tuples(model)
        variables = [
            (f"x[{var}]", x[var])
            for word_tuple in input_tuples + output_tuples
            for var in word_tuple
        ]
        constraints = []

        bit_perm = self._bit_perm()
        for output_word_idx, output_full_tuple in enumerate(output_tuples):
            output_bit_start = output_word_idx * model_word_size
            input_bit_indexes = [bit_perm[output_bit_start + i] for i in range(model_word_size)]
            input_word_indexes = {input_bit_index // model_word_size for input_bit_index in input_bit_indexes}

            if len(input_word_indexes) != 1:
                raise ValueError(
                    f"{self.id}: permutation mixes bits across model words "
                    f"(model.word_size={model_word_size}); unsupported in wordwise model"
                )

            input_word_idx = input_word_indexes.pop()
            input_full_tuple = input_tuples[input_word_idx]
            constraints.extend(
                x[output_class_var] == x[input_class_var]
                for output_class_var, input_class_var in zip(output_full_tuple[:2], input_full_tuple[:2])
            )
            for output_bit_offset, input_bit_index in enumerate(input_bit_indexes):
                input_bit_offset = input_bit_index % model_word_size
                constraints.append(
                    x[output_full_tuple[output_bit_offset + 2]] == x[input_full_tuple[input_bit_offset + 2]]
                )

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(self, model):
        """
        Return a list of MILP variables and constraints for PERMUTATION in the bitwise
        deterministic truncated XOR differential model (binary encoding).

        Each output class variable equals the corresponding permuted input class variable.
        Binary linking constraints are added for all input and output variables.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
            sage: component = cipher.component_from_id('permutation_0_0')
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: variables, constraints = component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)
            sage: variables
            [('x_class[plaintext_0]', x_0),
             ('x_class[plaintext_1]', x_1),
             ('x_class[plaintext_2]', x_2),
             ('x_class[plaintext_3]', x_3),
             ('x_class[permutation_0_0_0]', x_4),
             ('x_class[permutation_0_0_1]', x_5),
             ('x_class[permutation_0_0_2]', x_6),
             ('x_class[permutation_0_0_3]', x_7)]
        """
        x_class = model.trunc_binvar
        x = model.binary_variable

        input_ids, output_ids = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_ids + output_ids]

        input_id_tuples, output_id_tuples = self._get_input_output_variables_tuples()
        linking_constraints = model.link_binary_tuples_to_integer_variables(
            input_id_tuples + output_id_tuples, input_ids + output_ids
        )
        constraints = list(linking_constraints)

        bit_perm = self._bit_perm()
        for i, output_id in enumerate(output_ids):
            constraints.append(x_class[output_id] == x_class[input_ids[bit_perm[i]]])

        return variables, constraints

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
