import itertools

import pytest

from claasp.cipher_modules.models.sat.utils.matsui_bounds import (
    matsui_bounds_with_zero,
    matsui_lower_bound,
    matsui_weight_constraints,
    sequential_counter_with_all_prefixes,
)


def is_satisfiable(clauses, assignment=None):
    """Tiny DPLL with unit propagation for the CLAASP CNF string format (only for small toy instances)."""
    assignment = dict(assignment or {})
    clauses = [clause.split() for clause in clauses]
    while True:
        unit = None
        remaining = []
        for clause in clauses:
            literals = []
            satisfied = False
            for literal in clause:
                variable, value = literal.lstrip("-"), not literal.startswith("-")
                if variable not in assignment:
                    literals.append(literal)
                elif assignment[variable] == value:
                    satisfied = True
                    break
            if satisfied:
                continue
            if not literals:
                return False
            if len(literals) == 1:
                unit = literals[0]
            remaining.append(literals)
        if not remaining:
            return True
        if unit is None:
            break
        assignment[unit.lstrip("-")] = not unit.startswith("-")
        clauses = remaining
    variable = remaining[0][0].lstrip("-")
    remaining = [" ".join(clause) for clause in remaining]
    return any(is_satisfiable(remaining, {**assignment, variable: value}) for value in (True, False))


def all_assignments(variables):
    for bits in itertools.product((0, 1), repeat=len(variables)):
        yield bits, {variable: bool(bit) for variable, bit in zip(variables, bits)}


# Goal: the counter accepts exactly the assignments of weight at most the bound and forces every prefix-sum variable.
def test_sequential_counter_with_all_prefixes():
    variables = [f"x{i}" for i in range(5)]
    for weight in (1, 2, 3):
        counter_variables, constraints = sequential_counter_with_all_prefixes(variables, weight, "s")
        assert counter_variables == [f"s_{i}_{j}" for i in range(5) for j in range(weight)]
        for bits, assignment in all_assignments(variables):
            # satisfiable exactly when the sum is at most the weight
            assert is_satisfiable(constraints, assignment) == (sum(bits) <= weight)
            if sum(bits) > weight:
                continue
            # s_i_j is forced to be true whenever the first i + 1 variables sum to at least j + 1
            for i in range(5):
                for j in range(weight):
                    if sum(bits[: i + 1]) >= j + 1:
                        assert not is_satisfiable(constraints, {**assignment, f"s_{i}_{j}": False})


# Goal: a counter with a weight lower than 1 is rejected.
def test_sequential_counter_with_all_prefixes_rejects_zero_weight():
    with pytest.raises(ValueError, match="at least 1"):
        sequential_counter_with_all_prefixes(["x0"], 0, "s")


# Goal: exhaustively check that the constraints keep exactly the assignments satisfying the total and window bounds.
@pytest.mark.parametrize(
    "round_sizes, weight, matsui_bounds",
    [
        ([2, 2, 2], 4, [1, 2]),
        ([2, 2, 2], 3, [1, 2]),
        ([2, 2, 2], 5, [0, 1]),
        ([1, 3, 2], 4, [1, 1]),
        ([2, 0, 2, 2], 4, [0, 1, 2]),  # a round without weight variables
        ([3, 3], 4, [2]),
        ([4], 3, []),  # one round: no window
    ],
)
def test_matsui_weight_constraints_are_exactly_the_window_bounds(round_sizes, weight, matsui_bounds):
    number_of_rounds = len(round_sizes)
    hw_variables_by_round, index = [], 0
    for size in round_sizes:
        hw_variables_by_round.append([f"hw_{index + i}" for i in range(size)])
        index += size
    variables = [variable for round_variables in hw_variables_by_round for variable in round_variables]
    bounds = [0] + matsui_bounds
    windows = [(p, q) for p in range(number_of_rounds) for q in range(p, number_of_rounds)]
    windows.remove((0, number_of_rounds - 1))
    _, constraints = matsui_weight_constraints(hw_variables_by_round, weight, matsui_bounds)
    for bits, assignment in all_assignments(variables):
        round_weights = [
            sum(assignment[variable] for variable in round_variables) for round_variables in hw_variables_by_round
        ]
        expected = sum(bits) <= weight and all(
            sum(round_weights[p : q + 1]) <= weight - bounds[p] - bounds[number_of_rounds - 1 - q] for p, q in windows
        )
        # no trail respecting the bounds is removed, every trail violating them is removed
        assert is_satisfiable(constraints, assignment) == expected


# Goal: a weight below what the Matsui bounds allow gives unsatisfiable constraints.
def test_matsui_weight_constraints_below_the_lower_bound():
    # W = 2 < B_2 = 3: the window made by the last round is bounded by 2 - 3 < 0
    variables, constraints = matsui_weight_constraints([["x0"], ["x1"], ["x2"]], 2, [1, 3])
    assert variables == ["matsui_infeasible"]
    assert not is_satisfiable(constraints)


# Goal: with weight 0, every weight variable is simply forced to false.
def test_matsui_weight_constraints_with_zero_weight():
    assert matsui_weight_constraints([["x0"], ["x1"]], 0, [0]) == ([], ["-x0", "-x1"])


# Goal: the new variables use the given prefix.
def test_matsui_weight_constraints_prefix():
    variables, constraints = matsui_weight_constraints([["x0", "x1"], ["x2", "x3"]], 2, [1], prefix="p")
    assert all(variable.startswith("p_") for variable in variables)
    assert all(variable.lstrip("-").startswith(("p_", "x")) for clause in constraints for variable in clause.split())


# Goal: the bounds are prepended with 0, truncated to the rounds needed, and invalid input is rejected.
def test_matsui_bounds_with_zero():
    assert matsui_bounds_with_zero([2, 4, 8, 12], 4) == [0, 2, 4, 8]
    assert matsui_bounds_with_zero([], 1) == [0]
    with pytest.raises(ValueError, match="lowest weights of 1, ..., 3 rounds"):
        matsui_bounds_with_zero([2, 4], 4)
    with pytest.raises(ValueError, match="non-negative"):
        matsui_bounds_with_zero([-1], 2)


# Goal: the starting weight is the best split max_a(B_a + B_{r - a}), ignoring extra bounds.
def test_matsui_lower_bound():
    assert matsui_lower_bound([2, 4, 8], 4) == 10
    assert matsui_lower_bound([2, 4, 8, 100], 4) == 10
    assert matsui_lower_bound([0, 1, 3, 5], 5) == 5
    assert matsui_lower_bound([], 1) == 0
