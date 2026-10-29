"""Fractional S-box optima and bounds, checked against exact independent counts."""

import runpy
from fractions import Fraction
from io import StringIO
from math import log2, prod
from pathlib import Path

import pytest

from claasp.drivers.solvers import KissatSolver, SatStatus
from claasp.primitives import Heys
from claasp.primitives.toy_primitives.heys import HEYS_PERMUTATION, HEYS_SBOX
from claasp.representations.constraints.sat import WordDifferentialSATModel, WordLinearSATModel

pytestmark = pytest.mark.external


def _probability(result):
    return prod(
        abs(Fraction(step.transition.numerator, step.transition.denominator))
        for step in result.trail.steps
    )


def _heys_linear_oracle(input_mask=None):
    # Independent max-product dynamic programming over all 65,536 round masks.
    # Compute Walsh counts directly from the published substitution table.
    table = [
        [
            abs(
                sum(
                    (-1) ** (((a & x).bit_count() + (b & y).bit_count()) % 2)
                    for x, y in enumerate(HEYS_SBOX)
                )
            )
            // 4
            for b in range(16)
        ]
        for a in range(16)
    ]
    scores = [int(input_mask is None or state == input_mask) for state in range(65536)]
    scores[0] = 0
    for round_number in range(3):
        for shift in (0, 4, 8, 12):
            updated = [0] * 65536
            for state in range(65536):
                target = (state >> shift) & 15
                base = state & ~(15 << shift)
                updated[state] = max(
                    scores[base | (source << shift)] * table[source][target] for source in range(16)
                )
            scores = updated
        if round_number < 2:
            updated = [0] * 65536
            for state, score in enumerate(scores):
                permuted = sum(
                    ((state >> (15 - source)) & 1) << (15 - target)
                    for target, source in enumerate(HEYS_PERMUTATION)
                )
                updated[permuted] = score
            scores = updated
    return Fraction(max(scores), 4**12)


def test_three_round_heys_public_call_matches_exhaustive_round_mask_oracle():
    script = Path(__file__).parents[2] / "docs/examples/heys_fractional_trail.py"
    result = runpy.run_path(str(script))["result"]
    expected = _heys_linear_oracle()
    assert expected == Fraction(81, 512)
    assert _probability(result) == expected
    assert result.trail.total_weight == pytest.approx(-log2(expected))
    assert result.is_optimal and len(result.round_transitions) == 3
    assert "strict improvement proved UNSAT" in result.metadata.technique
    terminal = StringIO()
    result.to_terminal(file=terminal)
    assert "2.66015" in terminal.getvalue()
    assert "Proved optimal" in terminal.getvalue()


@pytest.mark.parametrize(
    "bound,expected", [(1, SatStatus.UNSATISFIABLE), (2, SatStatus.SATISFIABLE)]
)
def test_fractional_differential_bounds_use_actual_three_eighths_probability(bound, expected):
    model = WordDifferentialSATModel(
        Heys(number_of_rounds=1),
        maximum_weight=bound,
        fixed_input_differences={"plaintext": 0x2000, "key": 0},
        output_difference=0x5000,
    )
    solved = KissatSolver().solve(model.cnf_formula())
    assert solved.status is expected
    if solved.assignment is not None:
        trail = model.decode_characteristic(solved.assignment)
        assert prod(
            Fraction(s.transition.numerator, s.transition.denominator) for s in trail.steps
        ) == Fraction(3, 8)
        assert model.check_characteristic(trail)


@pytest.mark.parametrize("weight", [1, 2, 100])
def test_exact_integer_weight_query_does_not_round_a_fractional_trail(weight):
    model = WordDifferentialSATModel(
        Heys(number_of_rounds=1),
        fixed_weight=weight,
        fixed_input_differences={"plaintext": 0x2000, "key": 0},
        output_difference=0x5000,
    )
    assert KissatSolver().solve(model.cnf_formula()).status is SatStatus.UNSATISFIABLE


def test_linear_zero_weight_bound_rejects_fractional_transitions():
    model = WordLinearSATModel(
        Heys(number_of_rounds=1),
        maximum_weight=0,
        nonzero_input="plaintext",
        fixed_inputs={"key": 0},
    )
    assert KissatSolver().solve(model.cnf_formula()).status is SatStatus.UNSATISFIABLE


def test_probability_one_upper_bound_is_handled_without_an_invalid_solver_query():
    from claasp.primitives import BitVectorSBox

    # A direct sum with an identity bit has fractional transitions and a C=1 mask.
    primitive = BitVectorSBox(5, [(x & 16) | HEYS_SBOX[x & 15] for x in range(32)])
    result = primitive.analysis.find_optimal_trail(
        kind="xor_linear",
        fixed_input_masks={"input": 16},
    )
    assert result.is_optimal and _probability(result) == 1


def test_fractional_linear_transition_keeps_its_negative_correlation_sign():
    from dataclasses import replace

    from claasp.primitives import BitVectorSBox

    source, target = next(
        (a, b)
        for a in range(1, 16)
        for b in range(16)
        if sum(
            (-1) ** (((a & x).bit_count() + (b & y).bit_count()) % 2)
            for x, y in enumerate(HEYS_SBOX)
        )
        == -12
    )
    model = WordLinearSATModel(
        BitVectorSBox(lookup_table=HEYS_SBOX),
        maximum_weight=1,
        fixed_input_masks={"input": source},
    )
    formula = model.cnf_formula()
    indices = {name: number for number, name in enumerate(formula.variables, 1)}
    extra = tuple(
        (indices[name] if target & (1 << (3 - bit)) else -indices[name],)
        for bit, name in enumerate(model._shared._output)
    )
    bounded = replace(
        formula,
        clauses=formula.clauses + extra,
        provenance=formula.provenance + ("fixed_test_output_mask",) * len(extra),
    )
    solved = KissatSolver().solve(bounded)
    assert solved.status is SatStatus.SATISFIABLE
    result = model.decode_characteristic(solved.assignment)
    assert result.steps[0].transition.sign == -1
    assert abs(
        Fraction(result.steps[0].transition.numerator, result.steps[0].transition.denominator)
    ) == Fraction(3, 4)


def test_fractional_capable_table_still_accepts_exact_integer_weight_transitions():
    source, target = next(
        (a, b)
        for a in range(1, 16)
        for b in range(16)
        if sum(HEYS_SBOX[x] ^ HEYS_SBOX[x ^ a] == b for x in range(16)) == 8
    )
    model = WordDifferentialSATModel(
        Heys(number_of_rounds=1),
        fixed_weight=1,
        fixed_input_differences={"plaintext": source << 12, "key": 0},
        output_difference=target << 12,
    )
    solved = KissatSolver().solve(model.cnf_formula())
    assert solved.status is SatStatus.SATISFIABLE
    result = model.decode_characteristic(solved.assignment)
    assert result.total_weight == 1
    assert model.check_characteristic(result)


def test_three_round_heys_supports_the_tutorial_fixed_plaintext_mask():
    result = Heys(number_of_rounds=3).analysis.find_lowest_weight_xor_linear_trail(
        fixed_input_masks={"plaintext": 1},
        fixed_inputs={"key": 0},
    )
    assert result.trail.input_pattern.value == 1
    assert _probability(result) == _heys_linear_oracle(input_mask=1)
    assert result.is_optimal
