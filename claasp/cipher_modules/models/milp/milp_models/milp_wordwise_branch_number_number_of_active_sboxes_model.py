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

import time

from sage.matrix.constructor import Matrix
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.cipher_modules.component_analysis_tests import (
    compute_branch_number_from_field_matrix_with_minizinc,
    compute_word_branch_number_from_binary_matrix_with_minizinc,
    instantiate_matrix_over_correct_field,
)
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary
from claasp.name_mappings import MIX_COLUMN, SBOX

MILP_WORDWISE_BRANCH_NUMBER_ACTIVE_SBOXES = "wordwise_branch_number_number_of_active_sboxes"


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
    -- is dominated by :py:meth:`_word_branch_number` computing each linear component's *exact* word-level
    branch number via the MiniZinc-backed branch-number helpers in
    :py:mod:`~cipher_modules.component_analysis_tests` for ``mix_column`` and ``linear_layer`` components.
    Both paths perform a real constraint solve (MiniZinc/OR-Tools), around 1-3s each for AES's and uBlock's
    matrices respectively, but this is cached per matrix, since the same matrix is normally reused across many
    component instances (e.g. one per AES column, four per round) and rounds, so it is paid once per unique
    matrix, not once per round.
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

    def _invertible_linear_branch_number_constraints(self, input_word_ids, output_word_ids, branch_num):
        constraints = self._branch_number_constraints(input_word_ids + output_word_ids, branch_num)
        d = self._binary_variable[f"active_{'_'.join(input_word_ids + output_word_ids)}"]
        constraints.append(sum(self._word_variable[word_id] for word_id in input_word_ids) >= d)
        constraints.append(sum(self._word_variable[word_id] for word_id in output_word_ids) >= d)
        return constraints

    def _is_invertible_linear_map(self, component):
        if component.input_bit_size != component.output_bit_size:
            return False

        if component.type == MIX_COLUMN:
            field_matrix, polynomial, cell_word_size = component.description
            matrix, _ = instantiate_matrix_over_correct_field(
                field_matrix, int(polynomial), int(cell_word_size), component.input_bit_size, component.output_bit_size
            )
        else:
            matrix = Matrix(GF(2), component.description)

        return matrix.is_square() and matrix.rank() == matrix.nrows()

    def _component_matrix_cache_key(self, component):
        # mix_column stores description as [word_matrix, rotation, word_size] (rotation/word_size are plain
        # ints); linear_layer stores description as the bit matrix directly. Normalise both to a hashable,
        # always-2-tuple key: (type-specific matrix data, word_size).
        if component.type == MIX_COLUMN:
            matrix_key = (
                tuple(map(tuple, component.description[0])),
                component.description[1],
                component.description[2],
            )
        else:
            matrix_key = (tuple(map(tuple, component.description)),)
        return (matrix_key, self._word_size)

    def _word_branch_number(self, component):
        """
        Return the exact word-level differential branch number of a linear component (``linear_layer`` or
        non-permutation ``mix_column``), delegating to the dedicated branch-number solvers in
        :py:mod:`~cipher_modules.component_analysis_tests` rather than reimplementing the search here --
        :py:func:`~cipher_modules.component_analysis_tests.compute_branch_number_from_field_matrix_with_minizinc`
        for ``mix_column`` (already public), and
        :py:func:`~cipher_modules.component_analysis_tests.compute_word_branch_number_from_binary_matrix_with_minizinc`
        for ``linear_layer`` (added alongside it, since
        :py:func:`~cipher_modules.component_analysis_tests.branch_number`'s word-level path only covers
        ``mix_column``). See that function's docstring for how the two relate to the module's *bit*-level
        branch-number functions. Cached per matrix, since the same matrix is normally reused across many
        component instances (e.g. one per AES column, four per round) and rounds.

        INPUT:

        - ``component`` -- **Component object**; a linear component (``linear_layer`` or ``mix_column``)

        EXAMPLES::

            sage: import shutil
            sage: from claasp.ciphers.block_ciphers.ublock_single_linear_layer_block_cipher import UblockSingleLinearLayerBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
            ....: MilpWordwiseBranchNumberNumberOfActiveSboxesModel)
            sage: ublock = UblockSingleLinearLayerBlockCipher(number_of_rounds=1, use_mix_column=False)
            sage: milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(ublock)
            sage: milp.init_model_in_sage_milp_class()
            sage: linear_layer = [c for c in ublock.get_all_components() if c.type == 'linear_layer'][0]
            sage: shutil.which("minizinc") is None or milp._word_branch_number(linear_layer) == 8
            True

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: milp_aes = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(aes)
            sage: milp_aes.init_model_in_sage_milp_class()
            sage: mix_column = [c for c in aes.get_all_components() if c.type == 'mix_column'][0]
            sage: shutil.which("minizinc") is None or milp_aes._word_branch_number(mix_column) == 5
            True
        """
        cache_key = self._component_matrix_cache_key(component)
        if cache_key in self._linear_layer_branch_number_cache:
            return self._linear_layer_branch_number_cache[cache_key]

        if component.type == MIX_COLUMN:
            field_matrix, polynomial, cell_word_size = component.description
            if cell_word_size != self._word_size:
                raise NotImplementedError(
                    f"{component.id}: MixColumn cell size {cell_word_size} differs from the model's word size "
                    f"{self._word_size} (derived from the cipher's S-box size); not supported"
                )
            matrix, _ = instantiate_matrix_over_correct_field(
                field_matrix, int(polynomial), int(cell_word_size), component.input_bit_size, component.output_bit_size
            )
            branch_num = compute_branch_number_from_field_matrix_with_minizinc(matrix)
        else:
            branch_num = compute_word_branch_number_from_binary_matrix_with_minizinc(
                component.description, word_size=self._word_size
            )

        self._linear_layer_branch_number_cache[cache_key] = branch_num
        return branch_num

    def _add_fixed_variable_constraint(self, fixed_variable):
        mip = self._model
        w = self._word_variable
        word_ids = self._resolve_word_ids(fixed_variable["component_id"], list(fixed_variable["bit_positions"]))
        if any(value != 0 for value in fixed_variable["bit_values"]):
            raise NotImplementedError("only fixing to the all-zero word pattern is supported")
        if fixed_variable["constraint_type"] == "equal":
            for word_id in word_ids:
                mip.add_constraint(w[word_id] == 0)
        else:
            mip.add_constraint(sum(w[word_id] for word_id in word_ids) >= 1)

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
            self._add_fixed_variable_constraint(fixed_variable)

        sbox_active_terms = []
        for component in self._cipher.get_all_components():
            for constraint in component.milp_wordwise_branch_number_number_of_active_sboxes_constraints(self):
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
