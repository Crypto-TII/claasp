"""Exact SAT transition-model parity."""

from itertools import product

import pytest

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.sat import (
    ModularAddDeterministicTruncatedSATModel,
    ModularAddDifferentialSATModel,
    ModularAddLinearSATModel,
    ModularAddNWindowSATModel,
    ModularSubtractDeterministicTruncatedSATModel,
    SBoxXorDifferentialSATModel,
    SBoxXorLinearSATModel,
)
from claasp.semantics.cryptanalysis import (
    TruncatedXorDifference,
    truncated_modular_add,
    truncated_modular_subtract,
)


def _solutions(formula):
    for values in product((0, 1), repeat=len(formula.variables)):
        assignment = dict(zip(formula.variables, values))
        if formula.is_satisfied(assignment):
            yield assignment


@pytest.mark.parametrize(
    "model_type,transition_method",
    (
        (SBoxXorDifferentialSATModel, "xor_differential"),
        (SBoxXorLinearSATModel, "xor_linear"),
    ),
)
def test_sat_sbox_support_matches_every_present_pair(model_type, transition_method):
    model = model_type(PRESENT_SBOX)
    formula = model.cnf_formula()
    decoded = {
        (
            model.decode_transition(assignment).input_pattern.value,
            model.decode_transition(assignment).output_pattern.value,
        )
        for assignment in _solutions(formula)
    }
    expected = {
        (source, target)
        for source in range(16)
        for target in range(16)
        if getattr(model.semantics, transition_method)(source, target).is_possible
    }
    assert decoded == expected
    assert formula.constraint_models[0].model.backend is ConstraintBackend.SAT


@pytest.mark.parametrize("width", (1, 2, 3))
def test_sat_modadd_differential_matches_every_small_transition(width):
    model = ModularAddDifferentialSATModel(width)
    formula = model.cnf_formula()
    mask = (1 << width) - 1
    for left, right, output in product(range(1 << width), repeat=3):
        count = sum(
            (((x + y) & mask) ^ (((x ^ left) + (y ^ right)) & mask)) == output
            for x, y in product(range(1 << width), repeat=2)
        )
        fixed = {
            f"{prefix}_{bit}": (value >> (width - 1 - bit)) & 1
            for prefix, value in zip(("left", "right", "output"), (left, right, output))
            for bit in range(width)
        }
        accepted = [
            fixed | {f"weight_{bit}": value for bit, value in enumerate(weights)}
            for weights in product((0, 1), repeat=width - 1)
            if formula.is_satisfied(
                fixed | {f"weight_{bit}": value for bit, value in enumerate(weights)}
            )
        ]
        assert len(accepted) == int(bool(count))
        if accepted:
            assert model.decode_transition(accepted[0]).numerator == count


def test_sat_modadd_linear_matches_every_three_bit_mask_triple():
    model = ModularAddLinearSATModel(3)
    decoded = {
        (
            transition.input_pattern.value,
            transition.output_pattern.value,
            transition.numerator,
            transition.sign,
        )
        for assignment in _solutions(model.cnf_formula())
        for transition in (model.decode_transition(assignment),)
    }
    expected = {
        (
            transition.input_pattern.value,
            transition.output_pattern.value,
            transition.numerator,
            transition.sign,
        )
        for left, right, output in product(range(8), repeat=3)
        for transition in (model.semantics.xor_linear(left, right, output),)
        if transition.is_possible
    }
    assert decoded == expected


@pytest.mark.parametrize("window_size", range(4))
def test_sat_modadd_n_window_matches_direct_carry_difference_definition(window_size):
    model = ModularAddNWindowSATModel(4, window_size)
    formula = model.cnf_formula()
    for left, right, output in product(range(16), repeat=3):
        assignment = {
            f"{prefix}_{bit}": (value >> (3 - bit)) & 1
            for prefix, value in zip(("left", "right", "output"), (left, right, output))
            for bit in range(4)
        }
        carries = tuple(
            assignment[f"left_{bit}"] ^ assignment[f"right_{bit}"] ^ assignment[f"output_{bit}"]
            for bit in range(3)
        )
        assignment.update(zip(model.carry_difference_names, carries))
        assignment.update(
            (name, int(all(carries[start : start + window_size])))
            for start, name in enumerate(model.full_window_names)
        )
        run_length = window_size + 1
        expected = not any(
            all(carries[start : start + run_length])
            for start in range(len(carries) - run_length + 1)
        )
        assert formula.is_satisfied(assignment) is expected
    assert formula.constraint_models[0].model is model.model_provenance


@pytest.mark.parametrize(
    "model_type,semantics",
    (
        (ModularAddDeterministicTruncatedSATModel, truncated_modular_add),
        (ModularSubtractDeterministicTruncatedSATModel, truncated_modular_subtract),
    ),
)
def test_sat_modular_deterministic_truncated_matches_every_two_bit_pattern(model_type, semantics):
    model = model_type(2)
    formula = model.cnf_formula()

    def boundary_assignment(prefix, pattern):
        return {
            f"{prefix}_{bit}_{field}": value
            for bit, encoded in enumerate(model.encode_pattern(pattern))
            for field, value in zip(("unknown", "value"), encoded)
        }

    patterns = tuple("".join(bits) for bits in product("01?", repeat=2))
    for left, right in product(patterns, repeat=2):
        expected = str(
            semantics(TruncatedXorDifference.parse(left), TruncatedXorDifference.parse(right))
        )
        for output in patterns:
            boundary = (
                boundary_assignment("left", left)
                | boundary_assignment("right", right)
                | boundary_assignment("output", output)
            )
            witnesses = []
            for carry_bits in product((0, 1), repeat=4):
                assignment = boundary | {
                    f"carry_{bit}_{field}": value
                    for bit in range(2)
                    for field, value in zip(("unknown", "value"), carry_bits[2 * bit : 2 * bit + 2])
                }
                if formula.is_satisfied(assignment):
                    witnesses.append(assignment)
            assert bool(witnesses) is (output == expected)
            if witnesses:
                assert tuple(map(str, model.decode_transition(witnesses[0]))) == (
                    left,
                    right,
                    output,
                )
