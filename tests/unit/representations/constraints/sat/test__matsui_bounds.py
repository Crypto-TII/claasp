"""Exhaustively compare Matsui counters to the numerical window inequalities."""

from itertools import product

import pytest

from claasp.drivers.solvers import Z3Solver
from claasp.representations.constraints.sat._matsui_bounds import (
    _bounded_formula,
    _validated_bounds,
)
from claasp.representations.constraints.sat.model import CNFFormula


@pytest.mark.external
@pytest.mark.parametrize("groups,bounds", [((2, 0, 1), (0, 1, 1)), ((1,), (0,)), ((0, 1), (0, 2))])
def test_every_assignment_matches_all_consecutive_window_bounds(groups, bounds):
    names = tuple(f"x{i}" for i in range(sum(groups)))
    rounds, start = [], 0
    for size in groups:
        rounds.append(names[start : start + size])
        start += size
    base = CNFFormula(names, (), ())
    solver = Z3Solver()
    for maximum in range(sum(groups) + 1):
        formula = _bounded_formula(base, names, rounds, maximum, bounds)
        for values in product((0, 1), repeat=len(names)):
            assignment = dict(zip(names, values))
            expected = sum(values) <= maximum and all(
                sum(assignment[name] for row in rounds[first:stop] for name in row)
                <= maximum - bounds[first] - bounds[len(rounds) - stop]
                for first in range(len(rounds))
                for stop in range(first + 1, len(rounds) + 1)
            )
            clauses = tuple((i if value else -i,) for i, value in enumerate(values, 1))
            fixed = CNFFormula(
                formula.variables,
                formula.clauses + clauses,
                formula.provenance + ("fixed",) * len(clauses),
            )
            result = solver.solve(fixed)
            assert (result.status.value == "satisfiable") == expected
            if expected:
                assert fixed.is_satisfied(result.assignment)


@pytest.mark.parametrize("bounds", [[], [0, 0], [-1], [True], [0.5]])
def test_bounds_reject_wrong_length_and_noninteger_values(bounds):
    with pytest.raises(ValueError):
        _validated_bounds(bounds, 2)
