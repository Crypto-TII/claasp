from io import StringIO
from itertools import product

import pytest

from claasp.analysis.boomerang_search import BoomerangAnalysis, BoomerangSearchStatus
from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat._boomerang_switch import add_large_switch
from claasp.representations.constraints.sat.quasidifferential import _BooleanBuilder
from claasp.semantics.cryptanalysis import ModularAddBoomerangAutomaton

pytestmark = pytest.mark.external


def test_search_checks_trails_switches_and_proves_only_the_restricted_outer_objective():
    result = ToySpeck(4).analysis.find_lowest_weight_boomerang_trail(
        switch_round=2, solver=Z3Solver(timeout_seconds=30)
    )
    assert result.status is BoomerangSearchStatus.SATISFIABLE
    assert result.is_optimal
    assert result.trail is not None
    assert (
        result.trail.outer_weight
        == result.trail.upper.total_weight + result.trail.lower.total_weight
    )
    assert all(probability > 0 for _, _, probability in result.trail.switches)
    stream = StringIO()
    result.to_terminal(file=stream)
    assert "restricted model" in stream.getvalue()
    assert "outer weight" in stream.getvalue()


def test_zero_outer_differences_are_unsatisfiable_not_a_distinguisher():
    analysis = BoomerangAnalysis(ToySpeck(3), switch_round=1)
    for options in ({"input_difference": 0}, {"output_difference": 0}):
        result = analysis.find_lowest_weight_trail(**options)
        assert result.status is BoomerangSearchStatus.UNSATISFIABLE
        assert result.trail is None
        assert not result.is_optimal


def test_tampered_complete_assignment_is_rejected():
    model = BoomerangAnalysis(ToySpeck(3), switch_round=1).model()
    formula = model.cnf_formula(maximum_weight=2)
    solved = Z3Solver(timeout_seconds=30).solve(formula)
    assert solved.assignment is not None
    model.decode(solved.assignment)
    modified = dict(solved.assignment)
    fixed = next(name for name in formula.variables if name.startswith("upper_difference_key"))
    modified[fixed] = not modified[fixed]
    with pytest.raises(ValueError, match="invalid boomerang SAT witness"):
        model.decode(modified)


def test_small_encoded_switches_exhaustively_match_original_table_restriction():
    # width=2 has only one modeled carry position, so every switch with positive
    # probability is in the original at-most-one-halving subset.
    solver = Z3Solver(timeout_seconds=10)
    for values in product(range(4), repeat=4):
        builder = _BooleanBuilder()
        vectors = tuple(tuple(builder.fresh("difference") for _ in range(2)) for _ in range(4))
        add_large_switch(builder, *vectors)
        for vector, value in zip(vectors, values):
            for bit, literal in enumerate(vector):
                builder.require(literal if value & (1 << (1 - bit)) else -literal)
        solved = solver.solve(builder.formula())
        count = ModularAddBoomerangAutomaton(2).connectivity(*values).count
        assert (solved.status is SatStatus.SATISFIABLE) == (count >= 8)


def test_portable_backend_preserves_restricted_boomerang_search():
    import os

    from claasp.drivers.solvers import GLPKSolver, MinisatSolver, MiniZincSolver

    backend = os.environ.get("CLAASP_PARITY_BACKEND", "z3")
    driver = {
        "z3": lambda: Z3Solver(timeout_seconds=30),
        "minisat": lambda: MinisatSolver(timeout_seconds=30),
        "glpk": lambda: GLPKSolver(timeout_seconds=30),
        "minizinc": lambda: MiniZincSolver(
            os.environ.get("CLAASP_PARITY_CP_SOLVER", "gecode"), timeout_seconds=30
        ),
    }[backend]()
    analysis = BoomerangAnalysis(ToySpeck(3), switch_round=1)
    candidate = analysis.find_one_trail(solver=driver)
    assert candidate.status is BoomerangSearchStatus.SATISFIABLE
    assert candidate.trail is not None and candidate.trail.model_complete
    result = analysis.find_lowest_weight_trail(solver=driver)
    assert result.status is BoomerangSearchStatus.SATISFIABLE
    assert result.is_optimal and result.trail is not None
    assert result.trail.model_complete
