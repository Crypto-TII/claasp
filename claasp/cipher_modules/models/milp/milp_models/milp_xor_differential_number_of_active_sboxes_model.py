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

from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.milp.solvers import SOLVER_DEFAULT
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import (
    MILP_BUILDING_MESSAGE,
    MILP_XOR_DIFFERENTIAL_NUMBER_OF_ACTIVE_SBOXES,
    MILP_XOR_DIFFERENTIAL_OBJECTIVE,
)
from claasp.name_mappings import SBOX


class MilpXorDifferentialNumberOfActiveSboxesModel(MilpXorDifferentialModel):
    """
    MILP model that returns the true minimum number of active S-boxes over a fully bit-specified XOR differential
    trail (every difference bit is a concrete 0/1 value, exactly as in a real trail -- not a truncated/unknown-bit
    abstraction).

    This reuses the same exact, DDT-based S-box and bit-precise linear-layer propagation constraints as
    :py:class:`~MilpXorDifferentialModel` (used for :py:meth:`~MilpXorDifferentialModel.find_lowest_weight_xor_differential_trail`),
    including its already correct handling of bit-permutation diffusion layers such as uBlock's (via
    :py:meth:`~MixColumn.milp_constraints`, which expands the word-level permutation matrix to its bit-level
    equivalent). Each S-box already exposes an ``{sbox_id}_active`` binary indicator (1 iff its input difference
    is nonzero), set up by :py:meth:`~Sbox.milp_xor_differential_propagation_constraints`; the only change here is
    the objective, which sums these indicators instead of the weight/probability terms.

    Unlike the earlier attempt of building this on top of the *bitwise deterministic truncated* model: that model
    tracks a ternary {0, 1, unknown} class per bit, and "unknown" must be treated pessimistically as "possibly
    active" for soundness -- so as unknown bits spread through ARX-style mixing the reported count balloons well
    past the true minimum. Working with concrete 0/1 difference bits throughout avoids this entirely.
    """

    def add_constraints_to_build_in_sage_milp_class(self, fixed_variables=[]):
        """
        Take the constraints contained in self._model_constraints and add them to the build-in sage class.

        The MILP objective is set to the number of active S-boxes, rather than the sum of S-box differential
        probabilities (weight).

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_number_of_active_sboxes_model import (
            ....: MilpXorDifferentialNumberOfActiveSboxesModel)
            sage: ublock = UblockBlockCipher(number_of_rounds=1)
            sage: milp = MilpXorDifferentialNumberOfActiveSboxesModel(ublock)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.add_constraints_to_build_in_sage_milp_class()
        """
        self._verbose_print(MILP_BUILDING_MESSAGE)

        self.build_xor_differential_trail_model(-1, fixed_variables)
        mip = self._model
        p = self._integer_variable
        x = self._binary_variable
        for constraint in self._model_constraints:
            mip.add_constraint(constraint)

        sbox_ids = [component.id for component in self._cipher.get_all_components() if component.type == SBOX]
        mip.add_constraint(p[MILP_XOR_DIFFERENTIAL_OBJECTIVE] == sum(x[f"{sbox_id}_active"] for sbox_id in sbox_ids))

    def find_lowest_number_of_active_sboxes(self, fixed_values=[], solver_name=SOLVER_DEFAULT, external_solver_name=None):
        """
        Return the solution representing an XOR differential trail with the lowest number of active S-boxes.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in standard format (see
          :py:meth:`~cipher_modules.models.utils.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call
        - ``external_solver_name`` -- **string** (default: None); if specified, the library will write the internal
          Sagemath MILP model as a .lp file and solve it outside of Sagemath, using the external solver.

        EXAMPLE::

            sage: from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
            sage: from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_number_of_active_sboxes_model import (
            ....: MilpXorDifferentialNumberOfActiveSboxesModel)
            sage: ublock = UblockBlockCipher(number_of_rounds=1)
            sage: milp = MilpXorDifferentialNumberOfActiveSboxesModel(ublock)
            sage: trail = milp.find_lowest_number_of_active_sboxes(get_single_key_scenario_format_for_fixed_values(ublock)) # doctest: +SKIP
            ...
            sage: trail['total_weight'] # doctest: +SKIP
            1.0
        """
        start = time.time()
        self.init_model_in_sage_milp_class(solver_name)
        self._verbose_print(f"Solver used : {solver_name} (Choose Gurobi for Better performance)")
        mip = self._model
        p = self._integer_variable
        mip.set_objective(p[MILP_XOR_DIFFERENTIAL_OBJECTIVE])

        self.add_constraints_to_build_in_sage_milp_class(fixed_values)
        end = time.time()
        building_time = end - start
        solution = self.solve(MILP_XOR_DIFFERENTIAL_NUMBER_OF_ACTIVE_SBOXES, solver_name, external_solver_name)
        solution["building_time"] = building_time

        return solution

    def _parse_solver_output(self):
        """
        Parse the internal-solver (non-external) solution. The objective is a plain count of active S-boxes,
        so -- unlike the parent :py:class:`~MilpXorDifferentialModel`, whose objective is a weight_precision-scaled
        probability -- it must not be divided by ``10 ** weight_precision``.
        """
        mip = self._model
        objective_variables = mip.get_values(self._integer_variable)
        objective_value = objective_variables[MILP_XOR_DIFFERENTIAL_OBJECTIVE]
        components_variables = mip.get_values(self._binary_variable)
        components_values = self._get_component_values(objective_variables, components_variables)

        return objective_value, components_values
