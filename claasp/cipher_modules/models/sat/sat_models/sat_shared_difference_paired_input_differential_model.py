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
from copy import deepcopy

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import set_component_solution


def add_prefix_id_to_components(cipher, prefix):
    all_components = cipher.rounds.get_all_components()
    for component in all_components:
        component.set_id(f"{prefix}_{component.id}")
        new_input_id_links = [
            f"{prefix}_{input_id_link}" if input_id_link not in cipher.inputs else input_id_link
            for input_id_link in component.input_id_links
        ]

        component.set_input_id_links(new_input_id_links)

    return 0


class SharedDifferencePairedInputDifferentialModel(SatModel):
    def __init__(self, cipher):
        """
        Initialize the SharedDifferencePairedInputDifferentialModel object.

        This model duplicates the `cipher` and modifies component identifiers for differential
        analysis involving two distinct inputs (paired inputs `x` and `y`) and the same repeated
        difference (`a`). Specifically, this model searches for high-order XOR differential
        distinguishers characterized by the following formula:

        .. MATH::

            f(x) \oplus f(x + a) \oplus f(y) \oplus f(y + a)

        INPUT:

        - ``cipher`` -- cipher object to be analyzed.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_model import SharedDifferencePairedInputDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: model = SharedDifferencePairedInputDifferentialModel(speck)
        """
        cipher1 = cipher
        cipher2 = deepcopy(cipher)
        add_prefix_id_to_components(cipher1, "cipher1")
        for round_number in range(cipher.number_of_rounds):
            round_components2 = cipher2.get_components_in_round(round_number)
            cipher1._rounds.rounds[round_number]._components.extend(round_components2)
        self.differential_model = SatXorDifferentialModel(cipher1)
        self.duplicate_round_cipher = cipher1
        super().__init__(self.duplicate_round_cipher)

    def build_shared_difference_paired_input_differential_model(self, weight=-1, fixed_variables=[]):
        """
        Build the SAT model for searching high-order XOR differential distinguishers involving paired inputs
        and shared difference. The distinguisher follows the mathematical form:

        .. MATH::

            f(x) \oplus f(x + a) \oplus f(y) \oplus f(y + a)

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); fixes the trail weight if set to a non-negative integer.
        - ``fixed_variables`` -- **list** (default: `[]`); variables to fix, in standard format.

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_model import SharedDifferencePairedInputDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: model = SharedDifferencePairedInputDifferentialModel(speck)
            sage: model.build_shared_difference_paired_input_differential_model()
        """
        self.differential_model.build_xor_differential_trail_model(weight, fixed_variables)
        self._model_constraints = self.differential_model._model_constraints
        self._variables_list = self.differential_model._variables_list
        new_constraints = []
        for component in self._cipher.get_all_components():
            if (component.id.startswith("cipher1_") and "modadd" in component.id) or (
                component.id.startswith("cipher1_") and "modsub" in component.id
            ):
                component_copy_id = component.id.split("cipher1_")[1]
                for i in range(component.output_bit_size):
                    new_constraints.append(f"-cipher1_{component_copy_id}_{i} -{component_copy_id}_{i}")
        self._model_constraints.extend(new_constraints)
        self.differential_model._model_constraints.extend(new_constraints)

    def find_one_shared_difference_paired_input_differential_trail_with_fixed_weight(
        self, weight, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT, options=None
    ):
        """
        Return a single solution representing a high-order XOR differential trail for paired inputs (`x`, `y`)
        and repeated shared difference (`a`) with a fixed weight. The solution satisfies the mathematical condition:

        .. MATH::

            f(x) \oplus f(x + a) \oplus f(y) \oplus f(y + a)

        INPUT:

        - ``weight`` -- **integer**; the fixed weight of the differential trail.
        - ``fixed_values`` -- **list** (default: `[]`); fixed variables in standard format.
        - ``solver_name`` -- **string** (default: `CRYPTOMINISAT_EXT`); solver to use.

        .. SEEALSO::

            :ref:`sat-solvers`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_model import SharedDifferencePairedInputDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: fixed_variables = [
            ....:     set_fixed_variables(
            ....:         'plaintext',
            ....:         'equal',
            ....:         bit_positions=list(range(32)),
            ....:         bit_values=integer_to_bit_list(
            ....:             0x00102000,
            ....:             list_length=32,
            ....:             endianness='big'
            ....:         )
            ....:     ),
            ....:     set_fixed_variables(
            ....:         'key',
            ....:         'equal',
            ....:         bit_positions=list(range(64)),
            ....:         bit_values=integer_to_bit_list(
            ....:             0x0,
            ....:             list_length=64,
            ....:             endianness='big'
            ....:         )
            ....:     ),
            ....:     set_fixed_variables(
            ....:         'cipher_output_2_12',
            ....:         'equal',
            ....:         bit_positions=list(range(32)),
            ....:         bit_values=integer_to_bit_list(
            ....:             0x81028108,
            ....:             list_length=32,
            ....:             endianness='big'
            ....:         )
            ....:     )
            ....: ]
            sage: model = SharedDifferencePairedInputDifferentialModel(speck)
            sage: trail = model.find_one_shared_difference_paired_input_differential_trail_with_fixed_weight(
            ....:     11, fixed_values=fixed_variables
            ....: )
            sage: trail["status"]
            'SATISFIABLE'
        """
        start_time = time.time()
        self.build_shared_difference_paired_input_differential_model(weight, fixed_variables=fixed_values)
        solution = self.differential_model.solve(
            "SHARED_DIFFERENCE_PAIRED_INPUT_DIFFERENTIAL_MODEL", solver_name=solver_name, options=options
        )
        solution["building_time_seconds"] = time.time() - start_time
        solution["test_name"] = "find_one_shared_difference_paired_input_differential_model_trail"

        return solution

    def _parse_solver_output(self, variable2value):
        out_suffix = ""
        components_solutions = self._get_cipher_inputs_components_solutions(out_suffix, variable2value)
        total_weight = 0
        for component in self._cipher.get_all_components():
            hex_value = self._get_component_hex_value(component, out_suffix, variable2value)
            weight = self.calculate_component_weight(component, out_suffix, variable2value)
            component_solution = set_component_solution(hex_value, weight)
            components_solutions[f"{component.id}{out_suffix}"] = component_solution
            total_weight += weight

        return components_solutions, total_weight
