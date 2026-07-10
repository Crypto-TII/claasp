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

import itertools
import time

import numpy as np

from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary
from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    PERMUTATION_COMPONENT,
    SBOX,
    WORD_OPERATION,
)

MILP_WORDWISE_BRANCH_NUMBER_ACTIVE_SBOXES = "wordwise_branch_number_number_of_active_sboxes"


def _popcount64(a):
    """Vectorised population count for a numpy uint64 array (the classic SWAR bit trick), since the numpy
    version bundled with Sage predates ``numpy.bitwise_count`` (added in numpy 2.0)."""
    a = a - ((a >> np.uint64(1)) & np.uint64(0x5555555555555555))
    a = (a & np.uint64(0x3333333333333333)) + ((a >> np.uint64(2)) & np.uint64(0x3333333333333333))
    a = (a + (a >> np.uint64(4))) & np.uint64(0x0F0F0F0F0F0F0F0F)
    return (a * np.uint64(0x0101010101010101)) >> np.uint64(56)


class MilpWordwiseBranchNumberNumberOfActiveSboxesModel(MilpModel):
    """
    MILP model that returns the minimum number of active S-boxes, following the word-level technique of
    [MWGP2011]_ (Mouha, Wang, Gu, Preneel -- the paper that introduced MILP for this problem, illustrated on
    AES): one binary "is this word's difference nonzero" variable per word, XOR/linear-layer relations enforced
    via branch-number inequalities rather than bit-level DDT tables, and word-aligned permutations (bit
    rotations, uBlock-style word permutations) enforced via exact word equality.

    This is a different, and for permutation-heavy or ARX-mixing ciphers much cheaper, model than
    :py:class:`~MilpXorDifferentialNumberOfActiveSboxesModel`, which is bit-exact and DDT-based throughout and
    does not scale past a couple of rounds for such ciphers (see that class's docstring). The trade-off is
    scope: only cipher components with a *known branch number* (XOR, MixColumn/LinearLayer) or an *exact
    word-aligned permutation* (Rotate, Permutation, a permutation-flavoured MixColumn, pass-through components)
    are supported; components without a simple word-level differential model (AND, OR, modular addition/
    subtraction, non-word-aligned rotations or shifts) raise ``NotImplementedError``.

    [MWGP2011]_ reports that none of their AES optimization problems (up to 14 rounds) took longer than 0.40s
    to solve on a single core, using CPLEX. This model reproduces that magnitude: with the internal (GLPK)
    solver, real AES-128 rounds 1-2 solve in ~0.2-0.35s each including model build; rounds 3-4 grow to ~0.9s
    and ~2.5s respectively as GLPK's own branch-and-bound (a slower, open-source solver than CPLEX) starts to
    dominate. Model *build* time itself -- the part specific to this implementation, as opposed to the solver
    -- is consistently under 0.4s through round 4, thanks to two optimizations over a naive port of the
    technique: :py:meth:`_word_branch_number_bounded` computes each linear component's word-level branch
    number directly from plain-integer GF(2) arithmetic on the bit-expanded matrix rather than through
    :py:func:`~cipher_modules.component_analysis_tests.branch_number` (whose "bounded"/"sage" methods pay for
    Sage's generic finite-field arithmetic -- ~5-13s for a single 4x4 GF(2^8) AES MixColumn matrix, alone), and
    is cached per matrix (the same matrix is normally reused across many component instances -- e.g. one per
    AES column, four per round -- and across rounds); and the bounded enumeration over candidate word values is
    vectorised with numpy via a meet-in-the-middle split whenever the component's output fits in 64 bits (see
    :py:meth:`_min_output_word_weight_numpy`), which covers AES's MixColumn (32 bits) though not e.g. uBlock's
    128-bit consolidated linear layer (which falls back to :py:meth:`_min_output_word_weight_gray_code`).

    REFERENCES:

    .. [MWGP2011] Mouha, N., Wang, Q., Gu, D., Preneel, B. (2011). Differential and Linear Cryptanalysis using
       Mixed-Integer Linear Programming. Inscrypt 2011, LNCS 7537. https://mouha.be/wp-content/uploads/milp.pdf
    """

    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        super().__init__(cipher, n_window_heuristic, verbose)
        self._word_size = None
        self._word_variable = None
        self._linear_layer_branch_number_cache = {}

    def init_model_in_sage_milp_class(self, solver_name=SOLVER_DEFAULT):
        """
        Initialize a MILP instance from the build-in sage class, and determine the cipher's word size from its
        S-boxes.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
            ....: MilpWordwiseBranchNumberNumberOfActiveSboxesModel)
            sage: ublock = UblockBlockCipher(number_of_rounds=1)
            sage: milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(ublock)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.word_size
            4
        """
        super().init_model_in_sage_milp_class(solver_name=solver_name)
        self._word_variable = self._model.new_variable(binary=True)
        self._word_size = self._compute_word_size()

    def _compute_word_size(self):
        word_sizes = {component.input_bit_size for component in self._cipher.get_all_components() if component.type == SBOX}
        if len(word_sizes) != 1:
            raise ValueError("cipher must have exactly one, uniform S-box input size to determine the word size")
        return word_sizes.pop()

    def _own_word_ids(self, owner_id, bit_size):
        if bit_size % self._word_size != 0:
            raise NotImplementedError(f"{owner_id}: bit size {bit_size} is not a multiple of the word size {self._word_size}")
        return [f"{owner_id}_{k}" for k in range(bit_size // self._word_size)]

    def _resolve_word_ids(self, id_link, bit_positions):
        """
        Return the (already-defined) word ids that a producer's bit range decomposes into.

        Raises ``NotImplementedError`` if the range does not cleanly align to word boundaries of the producer's
        own word indexing.
        """
        if len(bit_positions) % self._word_size != 0:
            raise NotImplementedError(f"{id_link}: bit range of length {len(bit_positions)} is not a multiple of the word size")
        word_ids = []
        for k in range(len(bit_positions) // self._word_size):
            chunk = bit_positions[k * self._word_size : (k + 1) * self._word_size]
            if chunk[0] % self._word_size != 0 or chunk != list(range(chunk[0], chunk[0] + self._word_size)):
                raise NotImplementedError(f"{id_link}: bit range {chunk} is not aligned to the word size {self._word_size}")
            word_ids.append(f"{id_link}_{chunk[0] // self._word_size}")
        return word_ids

    def _flat_input_word_ids(self, component):
        """Return, for each input bit of ``component`` in flattened order, the word id that bit belongs to."""
        result = []
        for id_link, bit_positions in zip(component.input_id_links, component.input_bit_positions):
            for word_id in self._resolve_word_ids(id_link, bit_positions):
                result.extend([word_id] * self._word_size)
        return result

    def _resolved_input_word_ids(self, component):
        """Return one word id per input word, concatenated in input_id_links/input_bit_positions order."""
        word_ids = []
        for id_link, bit_positions in zip(component.input_id_links, component.input_bit_positions):
            word_ids.extend(self._resolve_word_ids(id_link, bit_positions))
        return word_ids

    def _branch_number_constraints(self, word_ids, branch_num):
        w = self._word_variable
        d = self._binary_variable[f"active_{'_'.join(word_ids)}"]
        constraints = [sum(w[word_id] for word_id in word_ids) >= branch_num * d]
        constraints += [d >= w[word_id] for word_id in word_ids]
        return constraints

    def _component_matrix_cache_key(self, component):
        # mix_column stores description as [word_matrix, rotation, word_size] (rotation/word_size are plain
        # ints); linear_layer stores description as the bit matrix directly. Normalise both to a hashable key.
        if component.type == MIX_COLUMN:
            return (
                tuple(map(tuple, component.description[0])),
                component.description[1],
                component.description[2],
                self._word_size,
            )
        return (tuple(map(tuple, component.description)), self._word_size)

    @staticmethod
    def _gf_multiply(a, b, reduction_constant, word_size):
        """Multiply ``a`` and ``b`` in GF(2**word_size) with the given (already-reduced, i.e. without the
        degree-word_size term) modulus, via the standard carry-less multiply-and-reduce algorithm."""
        result = 0
        high_bit = 1 << (word_size - 1)
        mask = (1 << word_size) - 1
        for _ in range(word_size):
            if b & 1:
                result ^= a
            carry = a & high_bit
            a = (a << 1) & mask
            if carry:
                a ^= reduction_constant
            b >>= 1
        return result

    def _mix_column_bit_columns(self, component, word_size):
        """Return, for a MixColumn field-matrix component, one integer per input bit whose binary expansion is
        that bit's contribution (as a column of the expanded bit matrix) to every output bit -- built directly
        from the field matrix via plain-integer GF(2**word_size) arithmetic (see :py:meth:`_gf_multiply`)."""
        field_matrix, polynomial, cell_word_size = component.description
        reduction_constant = polynomial & ((1 << cell_word_size) - 1)
        state_size = len(field_matrix)
        columns = [0] * (state_size * cell_word_size)
        for output_word, row in enumerate(field_matrix):
            for input_word, field_element in enumerate(row):
                if field_element == 0:
                    continue
                for input_bit_offset in range(cell_word_size):
                    product = self._gf_multiply(field_element, 1 << input_bit_offset, reduction_constant, cell_word_size)
                    if product == 0:
                        continue
                    column_index = input_word * cell_word_size + input_bit_offset
                    columns[column_index] |= product << (output_word * cell_word_size)
        return columns

    def _word_branch_number_bounded(self, component, max_input_word_weight=2):
        """
        Return the word-level differential branch number of an arbitrary linear component (``linear_layer`` or
        non-permutation ``mix_column``), computed by bounded enumeration over low-word-weight inputs at the
        *bit* level (via :py:func:`~cipher_modules.component_analysis_tests.binary_matrix_of_linear_component`),
        mirroring the bit-level bounded-enumeration fallback already used elsewhere in claasp for branch number
        computation, e.g. ``compute_branch_number_from_binary_matrix_with_bounded_enumeration``.

        This deliberately avoids :py:func:`~cipher_modules.component_analysis_tests.branch_number`. For
        ``mix_column`` it delegates to field-matrix computation (``compute_branch_number_from_field_matrix``),
        which -- for the "bounded"/"sage" methods -- pays for Sage's generic finite-field arithmetic on every
        candidate; measured at ~5.4s for a single 4x4 GF(2^8) AES MixColumn matrix (method="sage" did not
        return within 90s). Working with the *expanded bit matrix* directly and plain integer XOR sidesteps
        field arithmetic entirely, bringing that same computation under a millisecond. For ``linear_layer`` it
        is the only word-level option at all: ``branch_number()``'s word-level path only supports mix_column.

        Returns an upper bound on the true branch number (exact if the true minimum is achieved at input word
        weight <= ``max_input_word_weight``, which is typical since branch numbers are usually small -- e.g.
        AES's is 5, found here at weight 2). The result is cached per matrix, since the same matrix is normally
        reused unchanged across many component instances (e.g. one per AES column, four per round) and rounds.

        INPUT:

        - ``component`` -- **Component object**; a linear component (``linear_layer`` or ``mix_column``)
        - ``max_input_word_weight`` -- **integer** (default: `2`); maximum number of active input words tried

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_single_linear_layer_block_cipher import UblockSingleLinearLayerBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
            ....: MilpWordwiseBranchNumberNumberOfActiveSboxesModel)
            sage: ublock = UblockSingleLinearLayerBlockCipher(number_of_rounds=1, use_mix_column=False)
            sage: milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(ublock)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer = [c for c in ublock.get_all_components() if c.type == 'linear_layer'][0]
            sage: milp._word_branch_number_bounded(linear_layer, max_input_word_weight=1) # doctest: +SKIP
            12

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: milp_aes = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(aes)
            sage: milp_aes.init_model_in_sage_milp_class()
            sage: mix_column = [c for c in aes.get_all_components() if c.type == 'mix_column'][0]
            sage: milp_aes._word_branch_number_bounded(mix_column)
            5
        """
        cache_key = self._component_matrix_cache_key(component)
        if cache_key in self._linear_layer_branch_number_cache:
            return self._linear_layer_branch_number_cache[cache_key]

        word_size = self._word_size
        if component.type == MIX_COLUMN:
            # binary_matrix_of_linear_component() expands a MixColumn via linear_layer_to_binary_matrix(),
            # which evaluates the field-matrix multiplication through the generic cipher-evaluation machinery
            # on a random invertible probe matrix and then solves a linear system to recover the bit matrix --
            # ~13s for a single 4x4 GF(2^8) AES MixColumn. Building the bit matrix directly from the field
            # matrix via plain-integer GF(2^word_size) multiplication (the standard AES-style carry-less
            # multiply-and-reduce) is exact and takes well under a millisecond.
            n_bits = component.output_bit_size
            columns = self._mix_column_bit_columns(component, word_size)
        else:
            binary_matrix = binary_matrix_of_linear_component(component)
            n_bits = binary_matrix.nrows()
            columns = []
            for i in range(n_bits):
                col = 0
                for j in range(n_bits):
                    if binary_matrix[j, i]:
                        col |= 1 << j
                columns.append(col)
        n_words = n_bits // word_size
        # Fold each word_size-bit group's OR down into its lowest bit, then a single popcount gives the
        # word-weight in one step -- much cheaper than scanning n_words individually per candidate.
        low_bit_mask = sum(1 << (i * word_size) for i in range(n_words))

        def output_active_word_count(output_mask):
            folded = output_mask
            for shift in range(1, word_size):
                folded |= output_mask >> shift
            return (folded & low_bit_mask).bit_count()

        best = None
        for k in range(1, max_input_word_weight + 1):
            if best is not None and k >= best:
                break
            for word_subset in itertools.combinations(range(n_words), k):
                bit_indices = [w * word_size + offset for w in word_subset for offset in range(word_size)]
                bit_columns = [columns[idx] for idx in bit_indices]
                n_bits_here = len(bit_columns)
                if n_bits <= 64:
                    candidate = self._min_output_word_weight_numpy(bit_columns, low_bit_mask, word_size)
                else:
                    candidate = self._min_output_word_weight_gray_code(bit_columns, output_active_word_count)
                total = k + candidate
                if best is None or total < best:
                    best = total

        self._linear_layer_branch_number_cache[cache_key] = best
        return best

    @staticmethod
    def _min_output_word_weight_gray_code(bit_columns, output_active_word_count):
        """Return the minimum word-weight achievable by XOR-ing any nonempty subset of ``bit_columns``,
        via Gray-code enumeration (each successive candidate differs from the previous by exactly one column,
        so updating the running XOR is O(1) instead of O(len(bit_columns))). Used when the outputs are too wide
        (>64 bits) for the numpy fast path."""
        best = None
        output_mask = 0
        prev_gray = 0
        for i in range(1, 1 << len(bit_columns)):
            gray = i ^ (i >> 1)
            changed_bit = (gray ^ prev_gray).bit_length() - 1
            output_mask ^= bit_columns[changed_bit]
            prev_gray = gray
            weight = output_active_word_count(output_mask)
            if best is None or weight < best:
                best = weight
        return best

    @staticmethod
    def _min_output_word_weight_numpy(bit_columns, low_bit_mask, word_size):
        """Return the minimum word-weight achievable by XOR-ing any nonempty subset of ``bit_columns`` (each
        an integer < 2**64), via a numpy-vectorised meet-in-the-middle: split the columns into two halves,
        precompute every subset-XOR of each half (a small O(2**half) DP), then form and score every pairing
        of the two halves in one shot via broadcasting -- turning what would otherwise be millions of
        individual Python-level loop iterations (the dominant cost of building this model for e.g. a real
        AES MixColumn) into a handful of bulk array operations."""
        n = len(bit_columns)
        half = n // 2

        def subset_xor_sums(values):
            sums = np.zeros(1 << len(values), dtype=np.uint64)
            for i in range(1, 1 << len(values)):
                lsb = i & (-i)
                j = lsb.bit_length() - 1
                sums[i] = sums[i ^ lsb] ^ np.uint64(values[j])
            return sums

        left_sums = subset_xor_sums(bit_columns[:half])
        right_sums = subset_xor_sums(bit_columns[half:])
        combined = left_sums[:, None] ^ right_sums[None, :]

        folded = combined.copy()
        for shift in range(1, word_size):
            folded |= combined >> np.uint64(shift)
        weight_bits = folded & np.uint64(low_bit_mask)
        weights = _popcount64(weight_bits)
        weights[0, 0] = weights.max() + 1  # exclude the all-zero (empty subset) case
        return int(weights.min())

    def _component_constraints(self, component):
        output_ids = self._own_word_ids(component.id, component.output_bit_size)
        w = self._word_variable

        if component.type == CONSTANT:
            return [w[output_id] == 0 for output_id in output_ids]

        if component.type == SBOX:
            input_ids = self._resolved_input_word_ids(component)
            if len(input_ids) != 1 or len(output_ids) != 1:
                raise NotImplementedError(f"{component.id}: S-box input/output size does not match the word size")
            # A bijective S-box maps a zero input difference to a zero output difference, and (by injectivity)
            # a nonzero input difference to a nonzero output difference -- always, regardless of the DDT.
            return [w[output_ids[0]] == w[input_ids[0]]]

        if component.type in (INTERMEDIATE_OUTPUT, CIPHER_OUTPUT):
            input_ids = self._resolved_input_word_ids(component)
            if len(input_ids) != len(output_ids):
                raise NotImplementedError(f"{component.id}: pass-through component word count mismatch")
            return [w[output_id] == w[input_id] for output_id, input_id in zip(output_ids, input_ids)]

        if component.type == PERMUTATION_COMPONENT:
            return self._exact_permutation_constraints(component, output_ids, component._bit_perm())

        if component.type in (MIX_COLUMN, LINEAR_LAYER):
            if component.type == MIX_COLUMN and component._is_permutation_matrix():
                return self._mix_column_permutation_constraints(component, output_ids)
            return self._branch_number_constraints(
                self._resolved_input_word_ids(component) + output_ids,
                self._word_branch_number_bounded(component),
            )

        if component.type == WORD_OPERATION:
            operation = component.description[0]
            if operation == "XOR":
                return self._xor_constraints(component, output_ids)
            if operation == "NOT":
                input_ids = self._resolved_input_word_ids(component)
                if len(input_ids) != len(output_ids):
                    raise NotImplementedError(f"{component.id}: NOT word count mismatch")
                return [w[output_id] == w[input_id] for output_id, input_id in zip(output_ids, input_ids)]
            if operation == "ROTATE":
                return self._exact_permutation_constraints(component, output_ids, self._rotate_bit_perm(component))
            raise NotImplementedError(f"{component.id}: word operation '{operation}' is not supported by this model")

        raise NotImplementedError(f"{component.id}: component type '{component.type}' is not supported by this model")

    def _xor_constraints(self, component, output_ids):
        # A component's input_id_links/input_bit_positions entries do not necessarily correspond 1:1 to XOR
        # operands: several entries can concatenate into a single, wider operand (e.g. two 64-bit halves XORed
        # against one 128-bit round key). The true operand count is description[1]; operand o's words are the
        # o-th chunk of len(output_ids) words in the flattened input word list.
        number_of_operands = component.description[1]
        flat_input_ids = self._flat_input_word_ids(component)
        words_per_operand = len(output_ids)
        if len(flat_input_ids) != number_of_operands * words_per_operand * self._word_size:
            raise NotImplementedError(f"{component.id}: XOR input word count does not match operand count x output size")
        operand_word_groups = []
        for o in range(number_of_operands):
            operand_bits = flat_input_ids[o * words_per_operand * self._word_size : (o + 1) * words_per_operand * self._word_size]
            operand_word_groups.append([operand_bits[j * self._word_size] for j in range(words_per_operand)])
        constraints = []
        for j in range(len(output_ids)):
            group_words = [operand_words[j] for operand_words in operand_word_groups] + [output_ids[j]]
            constraints += self._branch_number_constraints(group_words, 2)
        return constraints

    def _rotate_bit_perm(self, component):
        rotation_amount = abs(component.description[1])
        input_len = component.output_bit_size
        if component.description[1] == rotation_amount:
            return [(i - rotation_amount) % input_len for i in range(input_len)]
        return [(i + rotation_amount) % input_len for i in range(input_len)]

    def _exact_permutation_constraints(self, component, output_ids, bit_perm):
        w = self._word_variable
        flat_input_ids = self._flat_input_word_ids(component)
        constraints = []
        for j, output_id in enumerate(output_ids):
            source_words = {flat_input_ids[bit_perm[j * self._word_size + offset]] for offset in range(self._word_size)}
            if len(source_words) != 1:
                raise NotImplementedError(f"{component.id}: output word {j} is not sourced from a single input word")
            constraints.append(w[output_id] == w[source_words.pop()])
        return constraints

    def _mix_column_permutation_constraints(self, component, output_ids):
        w = self._word_variable
        matrix = component.description[0]
        cell_size = component.description[2]
        if cell_size % self._word_size != 0:
            raise NotImplementedError(f"{component.id}: MixColumn cell size is not a multiple of the word size")
        words_per_cell = cell_size // self._word_size
        # _resolved_input_word_ids (one id per WORD) here, not _flat_input_word_ids (one id per BIT, with
        # each word's id repeated word_size times) -- indexing the latter with word-granularity offsets
        # like cell_k * words_per_cell + offset reads from the wrong, much-too-narrow range whenever
        # words_per_cell > 1, silently collapsing most of the permutation onto a handful of source words.
        input_ids = self._resolved_input_word_ids(component)
        constraints = []
        for cell_j, row in enumerate(matrix):
            cell_k = next(i for i, value in enumerate(row) if value != 0)
            for offset in range(words_per_cell):
                output_id = output_ids[cell_j * words_per_cell + offset]
                input_id = input_ids[(cell_k * words_per_cell + offset)]
                constraints.append(w[output_id] == w[input_id])
        return constraints

    def build_wordwise_branch_number_number_of_active_sboxes_model(self, fixed_variables=[]):
        """
        Build the MILP model for the minimum number of active S-boxes, using word-level branch-number
        constraints.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format. Only fixing a full input to the all-zero word pattern (``equal``) or excluding it
          (``not_equal``) is supported -- e.g. as produced by
          :py:meth:`~cipher_modules.models.utils.get_single_key_scenario_format_for_fixed_values`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
            ....: MilpWordwiseBranchNumberNumberOfActiveSboxesModel)
            sage: ublock = UblockBlockCipher(number_of_rounds=1)
            sage: milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(ublock)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_active_terms = milp.build_wordwise_branch_number_number_of_active_sboxes_model()
        """
        mip = self._model
        w = self._word_variable

        for cipher_input, input_bit_size in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            self._own_word_ids(cipher_input, input_bit_size)

        for fixed_variable in fixed_variables:
            word_ids = self._resolve_word_ids(fixed_variable["component_id"], list(fixed_variable["bit_positions"]))
            if any(value != 0 for value in fixed_variable["bit_values"]):
                raise NotImplementedError("only fixing to the all-zero word pattern is supported")
            if fixed_variable["constraint_type"] == "equal":
                for word_id in word_ids:
                    mip.add_constraint(w[word_id] == 0)
            else:
                mip.add_constraint(sum(w[word_id] for word_id in word_ids) >= 1)

        sbox_active_terms = []
        for component in self._cipher.get_all_components():
            for constraint in self._component_constraints(component):
                mip.add_constraint(constraint)
            if component.type == SBOX:
                sbox_active_terms.append(w[self._own_word_ids(component.id, component.output_bit_size)[0]])

        if not sbox_active_terms:
            raise ValueError("cipher has no S-boxes")
        mip.add_constraint(sum(sbox_active_terms) >= 1)

        return sbox_active_terms

    def find_lowest_number_of_active_sboxes(self, fixed_values=[], solver_name=SOLVER_DEFAULT):
        """
        Return the solution representing the minimum number of active S-boxes.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in standard format (see
          :py:meth:`~cipher_modules.models.utils.set_fixed_variables`); typically
          :py:meth:`~cipher_modules.models.utils.get_single_key_scenario_format_for_fixed_values`
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
            ....: MilpWordwiseBranchNumberNumberOfActiveSboxesModel)
            sage: ublock = UblockBlockCipher(number_of_rounds=1)
            sage: milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(ublock)
            sage: trail = milp.find_lowest_number_of_active_sboxes(get_single_key_scenario_format_for_fixed_values(ublock)) # doctest: +SKIP
            ...
            sage: trail['total_weight'] # doctest: +SKIP
            1.0
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        mip = self._model
        sbox_active_terms = self.build_wordwise_branch_number_number_of_active_sboxes_model(fixed_values)
        mip.set_objective(sum(sbox_active_terms))
        building_time = time.time() - start

        solve_start = time.time()
        status = "UNSATISFIABLE"
        objective_value = None
        try:
            objective_value = mip.solve()
            status = "SATISFIABLE"
        except Exception:
            pass
        solve_time = time.time() - solve_start

        solution = convert_solver_solution_to_dictionary(
            self._cipher.id, MILP_WORDWISE_BRANCH_NUMBER_ACTIVE_SBOXES, solver_name, solve_time, None, {}, objective_value
        )
        solution["status"] = status
        solution["building_time"] = building_time

        return solution

    @property
    def word_size(self):
        return self._word_size
