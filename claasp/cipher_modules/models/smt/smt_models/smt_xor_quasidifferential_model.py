# ****************************************************************************
#Copyright 2023 Technology Innovation Institute
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
# XOR Quasidifferential SMT Model
# ****************************************************************************

import time

from claasp.cipher_modules.models.smt import solvers
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.smt.utils import constants, utils
from claasp.cipher_modules.models.smt.utils.utils import (
    deinterleave_qdt_matrix,
    generate_weight_tables,
    quasidifferential_transition_matrix,
)

from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values, set_component_solution

from claasp.name_mappings import (
    CIPHER_OUTPUT,
    CONSTANT,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    PERMUTATION_COMPONENT,
    SBOX,
    WORD_OPERATION,
    XOR_QUASIDIFFERENTIAL,
)


class SmtXorQuasidifferentialModel(SmtModel):
    def __init__(self, cipher, counter="sequential"):
        super().__init__(cipher, counter)
        self.sboxes_qdt_templates = {}
        self.sboxes_qdt_matrices = {}
    def build_xor_quasidifferential_trail_model(self, weight=-1, fixed_variables=[]):
        self._variables_list = []

        if fixed_variables == []:
            fixed_variables = get_single_key_scenario_format_for_fixed_values(self._cipher)

        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = (
            CIPHER_OUTPUT,
            CONSTANT,
            INTERMEDIATE_OUTPUT,
            LINEAR_LAYER,
            MIX_COLUMN,
            PERMUTATION_COMPONENT,
            SBOX,
            WORD_OPERATION,
        )

        operation_types = ("AND", "MODADD", "MODSUB", "NOT", "OR", "ROTATE", "SHIFT", "SHIFT_BY_VARIABLE_AMOUNT",  "XOR")
        
        for component in self._cipher.get_all_components():
            operation = component.description[0]

            if component.type not in component_types or (
                component.type == WORD_OPERATION and operation not in operation_types
            ):
                print(f"{component.id} not yet implemented")
                continue

            try:
                variables, component_constraints = component.smt_xor_quasidifferential_propagation_constraints(self)

            except NotImplementedError:
                print(f"{component.id} not yet implemented")

                continue

            self._variables_list.extend(variables)

            constraints.extend(component_constraints)

        if weight != -1:
            counter_variables, weight_constraints = self.weight_constraints(weight)

            self._variables_list.extend(counter_variables)

            constraints.extend(weight_constraints)

        self._variables_list.extend(self.cipher_input_variables())

        self._variables_list.extend(
            f"qdt_{variable_name}" for variable_name in self.cipher_input_variables()
        )

        self._declarations_builder()

        self._model_constraints = constants.MODEL_PREFIX + self._declarations + constraints + constants.MODEL_SUFFIX

    

    def _qdt_local_weight_variables(
        self,
        component,
        max_weight,
    ):
        return [f"hw_qdt_{component.id}_{i}" for i in range(int(max_weight))]

    def _qdt_weight_constraints(
        self,
        weight_variables,
        weight,
    ):
        return [variable if i < weight else utils.smt_not(variable) for i, variable in enumerate(weight_variables)]

    def calculate_component_weight(
        self,
        component,
        out_suffix,
        output_values_dict,
    ):
        """
        Calculate the local quasidifferential weight.

        Generalized to any component that declares hw_qdt_{component.id}_*
        weight-bit variables (currently: Sbox, via a thermometer
        encoding; And, via a single per-bit OR indicator -- see
        And.smt_xor_quasidifferential_propagation_constraints). For
        components with no such variables (XOR, LinearLayer, ...) the
        sum is naturally 0, since none match the prefix.
        """

        prefix = f"hw_qdt_{component.id}_"

        return sum(value for variable, value in output_values_dict.items() if variable.startswith(prefix))

    @staticmethod
    def get_qdt_transitions(weights):
        """
        Flatten a QDT weight table into explicit transitions.

        INPUT:

            weights[(b, a)][weight_loss] = [(v, u), ...]

        OUTPUT:

            [
                {
                    "a": ...,
                    "u": ...,
                    "b": ...,
                    "v": ...,
                    "weight": ...
                },
                ...
            ]
        """

        transitions = []

        for (b, a), weight_dict in weights.items():
            for weight_loss, mask_pairs in weight_dict.items():
                for v, u in mask_pairs:
                    transitions.append(
                        {
                            "a": a,
                            "u": u,
                            "b": b,
                            "v": v,
                            "weight": weight_loss,
                        }
                    )

        return transitions

    def _qdt_input_bit_ids(
        self,
        component,
    ):
        """
        Return QDT mask variables corresponding to component inputs.
        """

        input_ids = []

        for input_id, bit_positions in zip(
            component.input_id_links,
            component.input_bit_positions,
        ):
            input_ids.extend([f"qdt_{input_id}_{position}" for position in bit_positions])

        return input_ids

    def _difference_input_bit_ids(
        self,
        component,
    ):
        """
        Return ordinary XOR difference variables corresponding
        to component inputs.
        """

        input_ids = []

        for input_id, bit_positions in zip(
            component.input_id_links,
            component.input_bit_positions,
        ):
            input_ids.extend([f"{input_id}_{position}" for position in bit_positions])

        return input_ids

    def _qdt_output_bit_ids(
        self,
        component,
    ):
        """
        Return QDT output mask bit identifiers.
        """

        return [f"qdt_{component.id}_{i}" for i in range(component.output_bit_size)]

    def _difference_output_bit_ids(
        self,
        component,
    ):
        """
        Return ordinary XOR difference output identifiers.
        """

        return [f"{component.id}_{i}" for i in range(component.output_bit_size)]

    def find_one_xor_quasidifferential_trail(
        self,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Find one XOR quasidifferential trail.
        """

        start_building_time = time.time()

        self.build_xor_quasidifferential_trail_model(fixed_variables=fixed_values)

        end_building_time = time.time()

        solution = self.solve(
            XOR_QUASIDIFFERENTIAL,
            solver_name=solver_name,
        )

        solution["building_time_seconds"] = end_building_time - start_building_time

        solution["test_name"] = "find_one_xor_quasidifferential_trail"

        return solution

    def find_one_xor_quasidifferential_trail_with_fixed_weight(
        self,
        fixed_weight,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Find one XOR quasidifferential trail with a fixed total
        weight loss.
        """

        start_building_time = time.time()

        self.build_xor_quasidifferential_trail_model(
            weight=fixed_weight,
            fixed_variables=fixed_values,
        )

        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, "dummy_hw_1")

        end_building_time = time.time()

        solution = self.solve(
            XOR_QUASIDIFFERENTIAL,
            solver_name=solver_name,
        )

        solution["building_time_seconds"] = end_building_time - start_building_time

        solution["test_name"] = "find_one_xor_quasidifferential_trail_with_fixed_weight"

        return solution

    def find_lowest_weight_xor_quasidifferential_trail(
        self,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Return the solution representing a quasidifferential trail
        with the lowest total weight loss.

        Mirrors SmtXorDifferentialModel.find_lowest_weight_xor_differential_trail:
        increases the weight bound from 0 until a solution is found.

        .. NOTE::

            There could be more than one trail with the lowest weight.
            Use :py:meth:`~find_all_xor_quasidifferential_trails_with_fixed_weight`
            to find all of them.
        """

        current_weight = 0

        start_building_time = time.time()
        self.build_xor_quasidifferential_trail_model(weight=current_weight, fixed_variables=fixed_values)
        end_building_time = time.time()

        solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)
        solution["building_time_seconds"] = end_building_time - start_building_time

        total_time = solution["solving_time_seconds"]
        max_memory = solution["memory_megabytes"]

        while solution["total_weight"] is None:
            current_weight += 1

            start_building_time = time.time()
            self.build_xor_quasidifferential_trail_model(weight=current_weight, fixed_variables=fixed_values)
            end_building_time = time.time()

            solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)
            solution["building_time_seconds"] = end_building_time - start_building_time

            total_time += solution["solving_time_seconds"]
            max_memory = max((max_memory, solution["memory_megabytes"]))

        solution["solving_time_seconds"] = total_time
        solution["memory_megabytes"] = max_memory
        solution["test_name"] = "find_lowest_weight_xor_quasidifferential_trail"

        return solution

    def _qdt_get_operands(self, solution):
        """
        Build the list of SMT literals that pin down a solution's
        primary-input boundary condition, for use in a blocking
        clause. Unlike the ordinary differential model's
        ``get_operands`` (which only needs to block the primary
        input DIFFERENCE, since the mask side does not exist there),
        a quasidifferential trail's boundary also includes the
        primary input MASK -- two trails sharing the same input
        difference but differing in input mask are genuinely
        different trails and must not be treated as duplicates.
        """

        operands = []

        for input_, bit_len in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            value_to_avoid = int(solution["components_values"][input_]["value"], base=16)
            operands.extend(
                [
                    utils.smt_not(f"{input_}_{j}") if value_to_avoid >> (bit_len - 1 - j) & 1 else f"{input_}_{j}"
                    for j in range(bit_len)
                ]
            )

            mask_to_avoid = int(solution["components_values"][input_].get("mask", "0x0"), base=16)
            operands.extend(
                [
                    utils.smt_not(f"qdt_{input_}_{j}")
                    if mask_to_avoid >> (bit_len - 1 - j) & 1
                    else f"qdt_{input_}_{j}"
                    for j in range(bit_len)
                ]
            )

        return operands

    def _is_nonlinear_component(
        self,
        component,
    ):
        """
        True for components that introduce genuine degrees of freedom
        into a quasidifferential trail, i.e. the ones whose specific
        (difference, mask) transition must be blocked when enumerating
        distinct trails.

        These are exactly the components with a nontrivial QDT: Sbox,
        AND and MODADD. Every other currently-implemented component
        (XOR, LinearLayer, Permutation, Rotate, MixColumn,
        CipherOutput, IntermediateOutput, Constant) is deterministic
        given its inputs on both the difference and the mask side, so
        blocking it would be redundant.

      
        """

        if SBOX in component.type:
            return True

        if component.type == WORD_OPERATION and component.description[0] in (
            "AND",
            "MODADD",
            "MODSUB",
            "OR",
        ):
            return True

        return False

    def _blocking_clause_operands(
        self,
        solution,
    ):
        """
        Build the full list of literals for a blocking clause that
        excludes exactly the trail described by `solution`: the primary
        input boundary (difference AND mask, via _qdt_get_operands)
        plus every nonlinear component's own difference and mask.
        """

        operands = self._qdt_get_operands(solution)

        for component in self._cipher.get_all_components():
            if not self._is_nonlinear_component(component):
                continue

            bit_len = component.output_bit_size

            value_to_avoid = int(solution["components_values"][component.id]["value"], base=16)
            operands.extend(
                [
                    utils.smt_not(f"{component.id}_{j}")
                    if value_to_avoid >> (bit_len - 1 - j) & 1
                    else f"{component.id}_{j}"
                    for j in range(bit_len)
                ]
            )

            mask_to_avoid = int(solution["components_values"][component.id].get("mask", "0x0"), base=16)
            operands.extend(
                [
                    utils.smt_not(f"qdt_{component.id}_{j}")
                    if mask_to_avoid >> (bit_len - 1 - j) & 1
                    else f"qdt_{component.id}_{j}"
                    for j in range(bit_len)
                ]
            )

        return operands

    def find_all_xor_quasidifferential_trails_with_fixed_weight(
        self,
        fixed_weight,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Return a list of solutions containing all the XOR
        quasidifferential trails having the ``fixed_weight`` total
        weight loss.

        Mirrors SmtXorDifferentialModel.find_all_xor_differential_trails_with_fixed_weight.
        A quasidifferential trail is fully determined by its
        primary-input boundary (difference AND mask -- see
        ``_qdt_get_operands``) together with the specific transition
        chosen at each NONLINEAR component (Sbox, AND, MODADD -- see
        ``_is_nonlinear_component``). Every other component (XOR,
        LinearLayer, Permutation, Rotate, MixColumn, ...) is fully
        deterministic given its inputs, on both the difference and the
        mask side, so it contributes no extra degrees of freedom to
        block on.
        """

        start_building_time = time.time()
        self.build_xor_quasidifferential_trail_model(weight=fixed_weight, fixed_variables=fixed_values)

        if self._counter == self._sequential_counter:
            self._sequential_counter_greater_or_equal(fixed_weight, "dummy_hw_1")

        end_building_time = time.time()

        solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)
        solution["building_time_seconds"] = end_building_time - start_building_time

        solutions_list = []

        while solution["total_weight"] is not None:
            solutions_list.append(solution)

            operands = self._blocking_clause_operands(solution)

            clause = utils.smt_or(operands)
            self._model_constraints = (
                self._model_constraints[: -len(constants.MODEL_SUFFIX)]
                + [utils.smt_assert(clause)]
                + constants.MODEL_SUFFIX
            )

            solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)
            solution["building_time_seconds"] = end_building_time - start_building_time
            solution["test_name"] = "find_all_xor_quasidifferential_trails_with_fixed_weight"

        return solutions_list

    def find_all_xor_quasidifferential_trails_with_weight_at_most(
        self,
        max_weight,
        min_weight=0,
        fixed_values=[],
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Return a list of solutions containing all the XOR
        quasidifferential trails having weight in
        ``[min_weight, max_weight]``.

        Mirrors SmtXorDifferentialModel.find_all_xor_differential_trails_with_weight_at_most.
        """

        solutions_list = []

        for weight in range(min_weight, max_weight + 1):
            solutions = self.find_all_xor_quasidifferential_trails_with_fixed_weight(
                weight, fixed_values=fixed_values, solver_name=solver_name
            )

            for solution in solutions:
                solution["test_name"] = "find_all_xor_quasidifferential_trails_with_weight_at_most"

            solutions_list.extend(solutions)

        return solutions_list

    def estimate_fixed_key_probability(
        self,
        max_weight,
        min_weight=0,
        fixed_values=[],
        fixed_masks=None,
        solver_name=solvers.SOLVER_DEFAULT,
    ):
        """
        Estimate a fixed-key correlation/probability by summing the
        SIGNED correlation of every quasidifferential trail found with
        weight in [min_weight, max_weight] (Beyne & Rijmen, Theorem 4.1
        / Equation 5): signed_correlation = sign * 2**(-weight), summed
        over all trails.

        INPUT:

        - ``max_weight`` / ``min_weight`` -- weight range to enumerate.
        - ``fixed_values`` -- ordinary DIFFERENCE constraints, built
          with set_fixed_variables as everywhere else in this codebase.
        - ``fixed_masks`` -- **list** (default: `None`); QDT MASK
          constraints, which set_fixed_variables cannot express (it
          only fixes ordinary difference bits, never qdt_-prefixed
          ones). Each entry is a dict:

          | {
          |     'component_id': 'plaintext',
          |     'bit_positions': range(64),
          |     'bit_values': [0] * 64
          |   }

          Theorem 4.1 requires the BOUNDARY masks to be zero
          (u_1 = u_{r+1} = 0) for the sum to equal the fixed-key
          probability of a specific differential -- pass those here,
          typically for the primary cipher inputs and the cipher
          output component.
        - ``solver_name`` -- the solver to use.

        This method runs its own build-and-enumerate loop (rather than
        delegating to find_all_xor_quasidifferential_trails_with_weight_at_most)
        precisely so that fixed_masks can be injected into the model
        after each rebuild -- the same _model_constraints manipulation
        technique already used by the sign cross-validation tests.
        Nothing outside this file is modified, so no other model
        (differential, linear, ...) that shares
        fix_variables_value_constraints is affected.

        Inherits the same known scaling limits as the underlying
        blocking-clause enumeration: practical mainly when most
        DIFFERENCES are already fixed (e.g. matching a known
        differential characteristic, as in rectangle.py's own
        reference script), leaving primarily masks to enumerate.

        Returns a dict with:

        - ``"trails"``: one entry per found trail, with its ``"sign"``,
          ``"weight"``, and signed ``"correlation"``;
        - ``"estimated_probability"``: the sum of all signed
          correlations;
        - ``"num_trails"``: how many trails were found and summed.
        """

        if fixed_masks is None:
            fixed_masks = []

        trails = []
        total = 0.0
        num_trails = 0

        for weight in range(min_weight, max_weight + 1):

            self.build_xor_quasidifferential_trail_model(
                weight=weight,
                fixed_variables=fixed_values,
            )

            if self._counter == self._sequential_counter:
                self._sequential_counter_greater_or_equal(weight, "dummy_hw_1")

            mask_constraints = self._build_fixed_mask_constraints(fixed_masks)

            if mask_constraints:
                self._model_constraints = (
                    self._model_constraints[: -len(constants.MODEL_SUFFIX)]
                    + mask_constraints
                    + constants.MODEL_SUFFIX
                )

            solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)

            while solution["total_weight"] is not None:

                sign = self.compute_trail_sign(solution)
                trail_weight = solution["total_weight"]
                signed_correlation = sign * (2.0 ** (-trail_weight))

                trails.append(
                    {
                        "sign": sign,
                        "weight": trail_weight,
                        "correlation": signed_correlation,
                    }
                )

                total += signed_correlation
                num_trails += 1

                operands = self._blocking_clause_operands(solution)

                clause = utils.smt_or(operands)
                self._model_constraints = (
                    self._model_constraints[: -len(constants.MODEL_SUFFIX)]
                    + [utils.smt_assert(clause)]
                    + constants.MODEL_SUFFIX
                )

                solution = self.solve(XOR_QUASIDIFFERENTIAL, solver_name=solver_name)

        return {
            "trails": trails,
            "estimated_probability": total,
            "num_trails": num_trails,
        }

    def _build_fixed_mask_constraints(
        self,
        fixed_masks,
    ):
        """
        Turn a fixed_masks list (see estimate_fixed_key_probability)
        into SMT assertions on the qdt_-prefixed mask variables.

        This is the mask-side counterpart of
        fix_variables_value_constraints, kept local to this file rather
        than extending that shared method (which is used by the
        differential, linear and other models).
        """

        constraints = []

        for entry in fixed_masks:
            component_id = entry["component_id"]
            bit_positions = entry["bit_positions"]
            bit_values = entry["bit_values"]

            for position, value in zip(bit_positions, bit_values):
                variable_name = f"qdt_{component_id}_{position}"

                if value:
                    constraints.append(utils.smt_assert(variable_name))
                else:
                    constraints.append(utils.smt_assert(utils.smt_not(variable_name)))

        return constraints

    def _parse_solver_output(
        self,
        variable2value,
    ):
        """
        Parse the solver output.

        The ordinary component value contains the XOR difference.
        The QDT masks are recorded alongside it (under the "mask"
        key of each component's solution) so that callers -- notably
        the blocking-clause logic in
        find_all_xor_quasidifferential_trails_with_fixed_weight --
        can distinguish trails that share the same differences but
        differ in their masks.
        """

        out_suffix = ""

        components_solutions = self._get_cipher_inputs_components_solutions(
            out_suffix,
            variable2value,
        )

        # The cipher-input entries built by _get_cipher_inputs_components_solutions
        # only carry the ordinary difference value; add their QDT mask
        # value too, using the same qdt_{input_id}_{position} naming
        # used everywhere else in this model.
        for input_id, bit_len in zip(self._cipher.inputs, self._cipher.inputs_bit_size):
            if input_id not in components_solutions:
                continue

            mask_value = 0

            for position in range(bit_len):
                mask_value <<= 1
                variable_name = f"qdt_{input_id}_{position}"

                if variable_name in variable2value:
                    mask_value ^= variable2value[variable_name]

            hex_digits = bit_len // 4 + (bit_len % 4 != 0)
            components_solutions[input_id]["mask"] = f"{mask_value:#0{hex_digits + 2}x}"

        total_weight = 0

        for component in self._cipher.get_all_components():
            hex_value = utils.get_component_hex_value(
                component,
                out_suffix,
                variable2value,
            )

            mask_hex_value = self._get_component_qdt_mask_hex_value(
                component,
                variable2value,
            )

            weight = self.calculate_component_weight(
                component,
                out_suffix,
                variable2value,
            )

            component_solution = set_component_solution(
                hex_value,
                weight,
            )

            component_solution["mask"] = mask_hex_value

            components_solutions[f"{component.id}{out_suffix}"] = component_solution

            total_weight += weight

        return (
            components_solutions,
            total_weight,
        )

    def _get_component_qdt_mask_hex_value(
        self,
        component,
        variable2value,
    ):
        """
        Same construction as claasp.cipher_modules.models.smt.utils.utils.get_component_hex_value,
        but reading the qdt_{component.id}_{i} mask variables instead
        of the ordinary {component.id}_{i} difference variables.
        """

        output_bit_size = component.output_bit_size

        value = 0

        for i in range(output_bit_size):
            value <<= 1

            variable_name = f"qdt_{component.id}_{i}"

            if variable_name in variable2value:
                value ^= variable2value[variable_name]

        hex_digits = output_bit_size // 4 + (output_bit_size % 4 != 0)

        return f"{value:#0{hex_digits + 2}x}"

    def _fixed_bit_constraints(
        self,
        bit_ids,
        value,
    ):
        """
        Fix a list of SMT Boolean variables to an integer value.
        """

        constraints = []

        size = len(bit_ids)

        for bit_id, bit_position in zip(
            bit_ids,
            range(size - 1, -1, -1),
        ):
            bit_value = (value >> bit_position) & 1

            if bit_value:
                constraints.append(utils.smt_assert(bit_id))
            else:
                constraints.append(utils.smt_assert(utils.smt_not(bit_id)))

        return constraints

    # TRAIL SIGN (post-processing on an already-solved trail)
    #
    # Everything above finds trails and their WEIGHT (-log2|correlation|).
    # This section computes the SIGN of the correlation for an
    # already-solved trail, mirroring rectangle.py's compute_sign,
    # common.py's compute_sign_speck, and simon_32.py's
    # correlation_sign_and -- but as pure Python post-processing on a
    # solved `solution` dict, exactly like those reference scripts do,
    # rather than as new SMT constraints (sign never affects the
    # weight-based SAT search itself, only the final numeric
    # correlation once a trail is found).
    #
    # Per Definition 4.1, a trail's correlation is the PRODUCT of each
    # component's local D^Fi coefficient, so the sign is the product of
    # each component's local sign. Only SBOX, AND, MODADD (Theorem 5.1
    # / 5.2's proofs) and CONSTANT (Theorem 3.2 (4)'s chi_v(t) factor)
    # contribute a sign other than +1; every other currently-implemented
    # component (XOR of data branches, LinearLayer, Permutation, Rotate,
    # MixColumn, CipherOutput, IntermediateOutput) is a pure linear or
    # identity map with a delta-function (always-nonnegative)
    # correlation (Theorem 3.2 (5)), contributing +1.

    def compute_trail_sign(
        self,
        solution,
    ):
        """
        Compute the overall correlation sign of an already-solved
        quasidifferential trail, e.g. as returned by
        find_one_xor_quasidifferential_trail or
        find_one_xor_quasidifferential_trail_with_fixed_weight.

        Returns +1 or -1.
        """

        components_solutions = solution["components_values"]

        sign = 1

        for component in self._cipher.get_all_components():

            if SBOX in component.type:
                sign *= self._sbox_local_sign(component, components_solutions)

            elif component.type == WORD_OPERATION and component.description[0] == "AND":
                sign *= self._and_local_sign(component, components_solutions)

            elif component.type == WORD_OPERATION and component.description[0] == "MODADD":
                sign *= self._modadd_local_sign(component, components_solutions)

            elif component.type == WORD_OPERATION and component.description[0] == "MODSUB":
                sign *= self._modsub_local_sign(component, components_solutions)

            elif component.type == WORD_OPERATION and component.description[0] == "OR":
                sign *= self._or_local_sign(component, components_solutions)

            elif component.type == WORD_OPERATION and component.description[0] == "NOT":
                sign *= self._not_local_sign(component, components_solutions)

            elif CONSTANT in component.type:
                sign *= self._constant_local_sign(component, components_solutions)

            # else: this component's local sign is +1 (pure linear or
            # identity map), so it does not affect the product.

        return sign

    @staticmethod
    def _parity(
        value,
    ):
        return bin(value).count("1") % 2

    def _bit_size_of(
        self,
        id_,
    ):
        """
        Return the bit width of a cipher input or a component's own
        output, given only its id string.
        """

        for input_id, input_bit_size in zip(
            self._cipher.inputs,
            self._cipher.inputs_bit_size,
        ):
            if input_id == id_:
                return input_bit_size

        for component in self._cipher.get_all_components():
            if component.id == id_:
                return component.output_bit_size

        raise ValueError(f"{id_}: unknown cipher input or component id")

    def _read_component_input_integer(
        self,
        component,
        field,
        components_solutions,
    ):
        """
        Reconstruct the full input integer (difference "value" or QDT
        "mask") for a component, by reading the requested bits from its
        upstream producers' (or primary inputs') already-solved hex
        value/mask, in the same order used everywhere else in this
        model to build input bit ids (_generate_input_ids,
        _qdt_input_bit_ids): for each (input_id, bit_positions) pair in
        component.input_id_links / component.input_bit_positions, in
        order, each position in bit_positions in order (position 0 =
        MSB of the upstream id's own value/mask).
        """

        result = 0

        for input_id, bit_positions in zip(
            component.input_id_links,
            component.input_bit_positions,
        ):
            upstream_size = self._bit_size_of(input_id)
            upstream_value = int(components_solutions[input_id][field], 16)

            for position in bit_positions:
                bit = (upstream_value >> (upstream_size - 1 - position)) & 1
                result = (result << 1) | bit

        return result

    def _read_component_input_operands(
        self,
        component,
        field,
        components_solutions,
        num_operands,
        word_size,
    ):
        """
        Like _read_component_input_integer, but split into
        `num_operands` separate word_size-bit integers (one per
        AND/MODADD operand), matching the same
        [:word_size], [word_size:2*word_size], ... slicing convention
        used by And/ModAdd's own
        smt_xor_quasidifferential_propagation_constraints.
        """

        full_bits = []

        for input_id, bit_positions in zip(
            component.input_id_links,
            component.input_bit_positions,
        ):
            upstream_size = self._bit_size_of(input_id)
            upstream_value = int(components_solutions[input_id][field], 16)

            for position in bit_positions:
                bit = (upstream_value >> (upstream_size - 1 - position)) & 1
                full_bits.append(bit)

        operands = []

        for operand_index in range(num_operands):
            operand_bits = full_bits[
                operand_index * word_size: (operand_index + 1) * word_size
            ]
            value = 0
            for bit in operand_bits:
                value = (value << 1) | bit
            operands.append(value)

        return operands

    def _sbox_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        Look up the sign of the sbox's QDT coefficient at the specific
        (a, u, b, v) point the solver found, directly from the cached
        deinterleaved QDT matrix (see Sbox.smt_xor_quasidifferential_propagation_constraints,
        which populates model.sboxes_qdt_matrices).
        """

        cache_key = str(component.description)
        qdt = self.sboxes_qdt_matrices.get(cache_key)

        if qdt is None:
            raise ValueError(
                f"{component.id}: no cached QDT matrix found for sign "
                f"lookup -- was smt_xor_quasidifferential_propagation_constraints "
                f"called for this sbox before solving?"
            )

        n = component.input_bit_size
        m = component.output_bit_size

        a = self._read_component_input_integer(component, "value", components_solutions)
        u = self._read_component_input_integer(component, "mask", components_solutions)
        b = int(components_solutions[component.id]["value"], 16)
        v = int(components_solutions[component.id]["mask"], 16)

        coefficient = qdt[(2**m) * b + v, (2**n) * a + u]

        if coefficient == 0:
            raise ValueError(
                f"{component.id}: the solved (a={a:#x}, u={u:#x}, "
                f"b={b:#x}, v={v:#x}) transition has a zero QDT "
                f"coefficient -- this should never happen for a valid "
                f"SAT solution."
            )

        return 1 if coefficient > 0 else -1

    def _and_local_sign(
        self,
        component,
        components_solutions,
    ):
        num_operands = component.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{component.id}: sign computation for AND is only "
                f"implemented for 2 operands."
            )

        word_size = component.output_bit_size

        a, b = self._read_component_input_operands(
            component, "value", components_solutions, 2, word_size
        )
        u, v = self._read_component_input_operands(
            component, "mask", components_solutions, 2, word_size
        )
        c = int(components_solutions[component.id]["value"], 16)

        return self._and_sign_word(a, b, c, u, v, word_size)

    def _modadd_local_sign(
        self,
        component,
        components_solutions,
    ):
        num_operands = component.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{component.id}: sign computation for MODADD is only "
                f"implemented for 2 operands."
            )

        word_size = component.output_bit_size

        a, b = self._read_component_input_operands(
            component, "value", components_solutions, 2, word_size
        )
        u, v = self._read_component_input_operands(
            component, "mask", components_solutions, 2, word_size
        )
        c = int(components_solutions[component.id]["value"], 16)
        w = int(components_solutions[component.id]["mask"], 16)

        return self._modadd_sign_word(a, b, c, u, v, w, word_size)

    def _not_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        chi_v(t) with t = all-ones: NOT is the affine map x -> x xor 1,
        so by Theorem 3.2 (4) its only contribution is the sign factor
        (-1)^(v . 1) = (-1)^popcount(v), where v is the component's
        output mask. Differences and masks themselves pass through
        unchanged (see
        Not.smt_xor_quasidifferential_propagation_constraints).
        """

        v = int(components_solutions[component.id]["mask"], 16)

        return -1 if self._parity(v) else 1

    def _or_local_sign(
        self,
        component,
        components_solutions,
    ):
        num_operands = component.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{component.id}: sign computation for OR is only "
                f"implemented for 2 operands."
            )

        word_size = component.output_bit_size

        a, b = self._read_component_input_operands(
            component, "value", components_solutions, 2, word_size
        )
        u, v = self._read_component_input_operands(
            component, "mask", components_solutions, 2, word_size
        )
        c = int(components_solutions[component.id]["value"], 16)
        w = int(components_solutions[component.id]["mask"], 16)

        return self._or_sign_word(a, b, c, u, v, w, word_size)

    def _modsub_local_sign(
        self,
        component,
        components_solutions,
    ):
        num_operands = component.description[1]

        if num_operands != 2:
            raise NotImplementedError(
                f"{component.id}: sign computation for MODSUB is only "
                f"implemented for 2 operands."
            )

        word_size = component.output_bit_size

        a, b = self._read_component_input_operands(
            component, "value", components_solutions, 2, word_size
        )
        u, v = self._read_component_input_operands(
            component, "mask", components_solutions, 2, word_size
        )
        c = int(components_solutions[component.id]["value"], 16)
        w = int(components_solutions[component.id]["mask"], 16)

        # MODSUB(a,b,c,u,v,w) == MODADD(c,b,a,w,v,u): see
        # _modsub_sign_word's note for the derivation and its
        # exhaustive verification.
        return self._modadd_sign_word(c, b, a, w, v, u, word_size)

    @staticmethod
    def _or_sign_word(
        a,
        b,
        c,
        u,
        v,
        w,
        word_size,
    ):
        """
        Word-level sign of a bitwise-OR quasidifferential transition.

        OR is AND conjugated by complementation
        (x1 | x2 = ~(~x1 & ~x2)). Complementation does not change
        differences, so OR's validity conditions and |coefficients| --
        and hence its WEIGHT -- are IDENTICAL to AND's; only the sign
        differs, by the translation factors of Theorem 3.2 (4).

        Verified by exhaustive brute force of Equation (4) on the
        1-bit case (all 64 combinations: same validity, same absolute
        value, sign ratio exactly (-1)^(u+v+w) per bit), then
        cross-checked at word level against the per-bit tensor product
        over 200000 random 4-bit vectors (8403 valid transitions, 0
        mismatches).

        Note that unlike AND's sign, OR's DOES depend on the output
        mask w.
        """

        base = SmtXorQuasidifferentialModel._and_sign_word(a, b, c, u, v, word_size)

        correction_parity = (
            SmtXorQuasidifferentialModel._parity(u)
            + SmtXorQuasidifferentialModel._parity(v)
            + SmtXorQuasidifferentialModel._parity(w)
        ) % 2

        return base * ((-1) ** correction_parity)

    def _constant_local_sign(
        self,
        component,
        components_solutions,
    ):
        """
        chi_v(t) = (-1)^(v . t): Theorem 3.2 (4), the translation-sign
        factor for a constant addition. The constant's own difference
        contribution is always 0 (see Constant.smt_xor_quasidifferential_propagation_constraints),
        so only its mask v and its known value t matter here.
        """

        t = int(component.description[0], 16)
        v = int(components_solutions[component.id]["mask"], 16)

        return -1 if self._parity(t & v) else 1

    @staticmethod
    def _and_sign_word(
        a,
        b,
        c,
        u,
        v,
        word_size,
    ):
        """
        Word-level sign of a bitwise-AND quasidifferential transition
        (Beyne & Rijmen, Theorem 5.1 and its proof in Appendix A.3),
        applied bit-independently across the whole word via Theorem
        3.2 (2) ("boxed maps": the sign of the word-level transition is
        the product of the per-bit signs, since each bit's AND is an
        independent sub-function acting on its own disjoint pair of
        input bits).

        Transliterated from simon_32.py's correlation_sign_and (the
        paper authors' own reference implementation) and verified
        against a direct brute-force evaluation of Equation (4) for
        the 1-bit case (29 valid transitions, 0 mismatches) before
        being encoded here.
        """

        mask = (1 << word_size) - 1

        comp_a = a ^ mask
        comp_b = b ^ mask
        comp_c = c ^ mask

        term1 = ((comp_a & u) ^ (c & v)) & ((comp_b & v) ^ (c & u))
        term2 = (u & v) & (c ^ (a & b & comp_c))

        p = SmtXorQuasidifferentialModel._parity(term1)
        q = SmtXorQuasidifferentialModel._parity(term2)

        return -1 if (p ^ q) else 1

    @staticmethod
    def _modadd_sign_word(
        a,
        b,
        c,
        u,
        v,
        w,
        word_size,
    ):
        """
        Word-level sign of a modular-addition quasidifferential
        transition (Beyne & Rijmen, Theorem 5.2), computed via the
        same AND-sign formula applied to the primed variables
        (a' = b xor c, b' = a xor c, c' = M+(a xor b xor c),
        u' = u xor w, v' = v xor w) -- since MODADD's theory is
        derived via CCZ-equivalence to a quadratic function "nearly
        the same as bitwise-and" (paper, Section 5.2 / Appendix A.4).

        Transliterated from common.py's compute_sign_speck (the paper
        authors' own reference implementation), using the SAME
        u' = u xor w / v' = v xor w substitution already used, and
        already verified, for the validity/weight constraints in
        ModAdd.smt_xor_quasidifferential_propagation_constraints --
        NOT compute_sign_speck's extra inter-round rotation logic,
        which is specific to how Speck wires masks between rounds and
        is already handled separately by claasp's own Rotate
        components.
        """

        mask = (1 << word_size) - 1

        abc_xor = a ^ b ^ c
        shifted_left = (abc_xor << 1) & mask
        c_prime = (abc_xor ^ shifted_left) >> 1

        a_prime = b ^ c
        b_prime = a ^ c
        u_prime = u ^ w
        v_prime = v ^ w

        return SmtXorQuasidifferentialModel._and_sign_word(
            a_prime, b_prime, c_prime, u_prime, v_prime, word_size
        )


      