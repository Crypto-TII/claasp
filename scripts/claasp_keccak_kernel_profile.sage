#!/usr/bin/env sage
"""Add Keccak kernel-profile trail search to CLAASP without patching CLAASP.

Run the fair Keccak-f[800] reproduction with MiniZinc CP-SAT:

    sage claasp_keccak_kernel_profile.sage \
        --rounds 3 \
        --profile KN --a-round 1 --upper-bound 32 \
        --core-weight-upper-bound 16 --processes 2 --time-limit 300

The default run does not prescribe the 4+4+24 round-weight split or a trail
witness.  Use ``--round-weight-split 4,4,24`` only for the faster guided run.
"""

import argparse
import json
import math
import time
from numbers import Integral
from pathlib import Path

from sage.crypto.sbox import SBox

from claasp.cipher_modules.models.cp.mzn_model import SOLVE_SATISFY
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
from claasp.cipher_modules.models.cp.solvers import CPSAT
from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, SATISFIABLE, SBOX, UNSATISFIABLE


class KeccakKernelProfileModel(MznXorDifferentialModel):
    """Runtime-only extension of CLAASP's MiniZinc XOR differential model."""

    def find_one_xor_differential_trail_with_kernel_profile(
        self,
        profile,
        a_round,
        upper_bound,
        core_weight_upper_bound=None,
        fixed_values=None,
        round_weight_split=None,
        solver_name=CPSAT,
        num_of_processors=None,
        timelimit=None,
        solve_external=False,
    ):
        """Find one trail with ``a -> lambda -> b -> chi -> c`` profile constraints.

        ``a_round`` is one-based.  Thus, for ``a_round=1``, state ``a`` is the
        output of round 1 and state ``c`` is the output of round 2.  A profile
        character ``K`` means zero column parity, while ``N`` means at least
        one nonzero column parity.

        The optional core bound is Mella et al.'s ``w_rev(a) + w(b)``.  The
        optional round split fixes the ordinary CLAASP probability weight in
        every round; it is intentionally omitted in the fair reproduction.
        """
        fixed_values = [] if fixed_values is None else fixed_values
        profile = self._validate_kernel_profile_arguments(
            profile,
            a_round,
            upper_bound,
            core_weight_upper_bound,
            round_weight_split,
        )

        build_start = time.perf_counter()
        self.build_xor_differential_trail_model(0, fixed_values)
        self._model_constraints.append(f"constraint weight <= {100 * upper_bound};")
        self._add_kernel_profile_constraints(
            profile,
            a_round,
            use_lane_translation_symmetry=not fixed_values,
        )
        if core_weight_upper_bound is not None:
            self._add_core_weight_constraint(a_round, core_weight_upper_bound)
        if round_weight_split is not None:
            self._add_round_weight_split_constraints(round_weight_split)
        self._install_kernel_search_order()
        build_time = time.perf_counter() - build_start

        solution = self.solve(
            "xor_differential_one_solution",
            solver_name=solver_name,
            timeout_in_seconds_=timelimit,
            processes_=num_of_processors,
            solve_external=solve_external,
        )
        solution["building_time_seconds"] = build_time
        solution["test_name"] = "find_one_xor_differential_trail_with_kernel_profile"
        solution["kernel_profile"] = profile
        solution["a_round"] = int(a_round)
        solution["core_weight_upper_bound"] = core_weight_upper_bound
        solution["round_weight_split"] = list(round_weight_split) if round_weight_split else None
        if solution.get("status") != UNSATISFIABLE:
            solution["round_weights"] = self._round_weights_from_solution(solution)

        return solution

    def _validate_kernel_profile_arguments(
        self,
        profile,
        a_round,
        upper_bound,
        core_weight_upper_bound,
        round_weight_split,
    ):
        if self._cipher.family_name != "keccak_sbox":
            raise NotImplementedError("this extension currently supports KeccakSboxPermutation only")
        if not isinstance(profile, str) or profile.upper() not in {"KK", "KN", "NK", "NN"}:
            raise ValueError("profile must be one of KK, KN, NK, or NN")
        if not isinstance(a_round, Integral) or not 1 <= a_round < self._cipher.number_of_rounds:
            raise ValueError("a_round must be a one-based, non-final round")
        if not isinstance(upper_bound, Integral) or upper_bound < 0:
            raise ValueError("upper_bound must be a nonnegative integer")
        if core_weight_upper_bound is not None and (
            not isinstance(core_weight_upper_bound, Integral) or core_weight_upper_bound < 0
        ):
            raise ValueError("core_weight_upper_bound must be a nonnegative integer or None")
        if round_weight_split is not None:
            if len(round_weight_split) != self._cipher.number_of_rounds:
                raise ValueError("round_weight_split must contain one value per round")
            if any(not isinstance(weight, Integral) or weight < 0 for weight in round_weight_split):
                raise ValueError("round_weight_split values must be nonnegative integers")
            if sum(round_weight_split) > upper_bound:
                raise ValueError("round_weight_split exceeds upper_bound")

        return profile.upper()

    def _round_output_component(self, round_number):
        candidates = [
            component
            for component in self._cipher.components_in_round(round_number)
            if component.type == CIPHER_OUTPUT
            or (component.type == INTERMEDIATE_OUTPUT and component.description == ["round_output"])
        ]
        if len(candidates) != 1:
            raise ValueError(f"expected one round output in round {round_number}, found {len(candidates)}")

        return candidates[0]

    def _add_kernel_profile_constraints(self, profile, a_round, use_lane_translation_symmetry):
        word_size = self._cipher.word_bit_size
        states = {
            "a": (self._round_output_component(a_round - 1).id, profile[0]),
            "c": (self._round_output_component(a_round).id, profile[1]),
        }
        parity_size = 5 * word_size
        bit_values = (16, 8, 4, 2, 1)

        for state_name, (component_id, kernel_class) in states.items():
            self._variables_declarations.extend(
                [
                    f"array[0..{parity_size - 1}] of var 0..2: kernel_{state_name}_half_column;",
                    f"array[0..{parity_size - 1}] of var 0..1: kernel_{state_name}_parity;",
                    f"array[0..{parity_size - 1}] of var 0..31: kernel_{state_name}_row;",
                ]
            )

            for x in range(5):
                for z in range(word_size):
                    parity_index = x * word_size + z
                    column_sum = "+".join(
                        f"{component_id}[{(y * 5 + x) * word_size + z}]" for y in range(5)
                    )
                    self._model_constraints.append(
                        f"constraint {column_sum} = 2 * kernel_{state_name}_half_column[{parity_index}] "
                        f"+ kernel_{state_name}_parity[{parity_index}];"
                    )

            for y in range(5):
                for z in range(word_size):
                    row_index = y * word_size + z
                    row_value = "+".join(
                        f"{bit_values[x]}*{component_id}[{(y * 5 + x) * word_size + z}]"
                        for x in range(5)
                    )
                    self._model_constraints.append(
                        f"constraint kernel_{state_name}_row[{row_index}] = {row_value};"
                    )

            relation = "= 0" if kernel_class == "K" else ">= 1"
            self._model_constraints.append(f"constraint sum(kernel_{state_name}_parity) {relation};")

        # Keccak differential trails are invariant under translation along z.
        # For a free nonzero-a search, choose the representative active at z=0.
        if use_lane_translation_symmetry and profile != "KK":
            a_component_id = states["a"][0]
            slice_zero = "+".join(
                f"{a_component_id}[{(y * 5 + x) * word_size}]" for x in range(5) for y in range(5)
            )
            self._model_constraints.append(f"constraint {slice_zero} >= 1;")

    def _add_core_weight_constraint(self, a_round, core_weight_upper_bound):
        sboxes = [
            component
            for component in self._cipher.components_in_round(a_round)
            if component.type == SBOX
        ]
        if not sboxes or any(component.output_bit_size != 5 for component in sboxes):
            raise ValueError("the selected round does not contain Keccak's 5-bit chi S-boxes")

        ddt = SBox(sboxes[0].description).difference_distribution_table()
        reverse_weights = []
        for output_difference in range(ddt.ncols()):
            compatible_weights = [
                int(round(100 * math.log2(32 / ddt[input_difference][output_difference])))
                for input_difference in range(ddt.nrows())
                if ddt[input_difference][output_difference]
            ]
            reverse_weights.append(min(compatible_weights))

        # For Keccak chi, all possible output differences for a fixed input
        # difference have the same weight, so the selected transition's p
        # variable is exactly w(b).
        for input_difference in range(ddt.nrows()):
            nonzero_counts = {count for count in ddt.rows()[input_difference] if count}
            if len(nonzero_counts) != 1:
                raise NotImplementedError("the S-box weight is not determined by b")

        self._variables_declarations.append(
            "array[0..31] of int: keccak_chi_reverse_weight = array1d(0..31, ["
            + ",".join(map(str, reverse_weights))
            + "]);"
        )
        word_size = self._cipher.word_bit_size
        reverse_terms = [
            f"keccak_chi_reverse_weight[kernel_a_row[{y * word_size + z}]]"
            for y in range(5)
            for z in range(word_size)
        ]
        forward_indices = [self.component_and_probability[component.id] for component in sboxes]
        self._variables_declarations.extend(
            [
                f"var int: kernel_core_reverse_weight = {'+'.join(reverse_terms)};",
                "var int: kernel_core_forward_weight = "
                + "+".join(f"p[{index}]" for index in forward_indices)
                + ";",
                "var int: kernel_core_weight = kernel_core_reverse_weight + kernel_core_forward_weight;",
            ]
        )
        self._model_constraints.append(
            f"constraint kernel_core_weight <= {100 * core_weight_upper_bound};"
        )

    def _add_round_weight_split_constraints(self, round_weight_split):
        for round_number, target_weight in enumerate(round_weight_split):
            probability_indices = [
                self.component_and_probability[component.id]
                for component in self._cipher.components_in_round(round_number)
                if component.type == SBOX
            ]
            if not probability_indices:
                raise ValueError(f"round {round_number} has no S-box probability variables")
            probability_sum = "+".join(f"p[{index}]" for index in probability_indices)
            self._model_constraints.append(f"constraint {probability_sum} = {100 * target_weight};")

    def _install_kernel_search_order(self):
        search = (
            "solve :: seq_search(["
            "int_search(kernel_a_row, first_fail, indomain_min, complete),"
            "int_search(kernel_c_row, first_fail, indomain_min, complete),"
            "int_search(kernel_c_parity, first_fail, indomain_min, complete)"
            "]) satisfy;"
        )
        self._model_constraints[self._model_constraints.index(SOLVE_SATISFY)] = search

    def _round_weights_from_solution(self, solution):
        values = solution["components_values"]
        return [
            sum(
                float(values[component.id]["weight"])
                for component in self._cipher.components_in_round(round_number)
                if component.type == SBOX
            )
            for round_number in range(self._cipher.number_of_rounds)
        ]


def parse_round_weight_split(value):
    if value is None:
        return None
    return tuple(int(part) for part in value.split(","))


def serializable_solution(solution):
    serializable = dict(solution)
    if "cipher" in serializable:
        serializable["cipher"] = str(serializable["cipher"])
    return serializable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--profile", default="KN")
    parser.add_argument("--a-round", type=int, default=1)
    parser.add_argument("--upper-bound", type=int, default=32)
    parser.add_argument("--core-weight-upper-bound", type=int, default=16)
    parser.add_argument("--round-weight-split", type=parse_round_weight_split)
    parser.add_argument("--processes", type=int, default=2)
    parser.add_argument("--time-limit", type=int, default=300, help="seconds")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    cipher = KeccakSboxPermutation(number_of_rounds=args.rounds, word_size=32)
    model = KeccakKernelProfileModel(cipher)

    wall_start = time.perf_counter()
    trail = model.find_one_xor_differential_trail_with_kernel_profile(
        profile=args.profile,
        a_round=args.a_round,
        upper_bound=args.upper_bound,
        core_weight_upper_bound=args.core_weight_upper_bound,
        round_weight_split=args.round_weight_split,
        solver_name=CPSAT,
        num_of_processors=args.processes,
        timelimit=args.time_limit,
    )
    wall_time = time.perf_counter() - wall_start
    trail["wall_time_seconds"] = wall_time

    summary = {
        "status": trail.get("status"),
        "total_weight": trail.get("total_weight"),
        "round_weights": trail.get("round_weights"),
        "kernel_profile": trail.get("kernel_profile"),
        "a_round": trail.get("a_round"),
        "solver": trail.get("solver_name", CPSAT),
        "solver_time_seconds": trail.get("solving_time_seconds"),
        "building_time_seconds": trail.get("building_time_seconds"),
        "wall_time_seconds": wall_time,
        "round_weight_split_was_fixed": args.round_weight_split is not None,
    }
    print(json.dumps(summary, indent=2))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(serializable_solution(trail), indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        print(f"Full trail written to {args.output}")

    if trail.get("status") != SATISFIABLE:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
