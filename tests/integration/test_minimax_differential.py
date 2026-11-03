from io import StringIO

import pytest

from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints.sat import KeyScheduleMinimaxSATModel

pytestmark = pytest.mark.external


def test_single_key_speck_preserves_the_original_legacy_minimax_five_fixture():
    result = Speck(number_of_rounds=4).analysis.find_minimax_xor_differential_trail(
        fixed_input_differences={"key": 0}, solver=Z3Solver(timeout_seconds=30)
    )
    assert result.is_optimal and result.trail is not None
    assert result.trail.objective_weight == result.trail.data_path_weight == 5
    assert result.trail.key_schedule_weight == 0


def test_related_key_minimax_is_distinct_from_the_sum_of_weights():
    primitive = ToySpeck(3)
    result = primitive.analysis.find_minimax_xor_differential_trail(
        fixed_input_differences={"key": 1, "plaintext": 1}
    )
    assert result.is_optimal and result.trail is not None
    assert result.trail.objective_weight == 3
    assert result.trail.key_schedule_weight > 0
    assert result.trail.data_path_weight > 0
    assert result.trail.total_weight > result.trail.objective_weight
    below = KeyScheduleMinimaxSATModel(
        primitive, fixed_input_differences={"key": 1, "plaintext": 1}
    )
    assert (
        Z3Solver().solve(below.cnf_formula(maximum_partition_weight=2)).status
        is SatStatus.UNSATISFIABLE
    )
    stream = StringIO()
    result.to_terminal(file=stream)
    assert "min-max objective" in stream.getvalue()
    assert "total characteristic weight" in stream.getvalue()


def test_impossible_user_bound_returns_unsat_without_a_false_optimality_claim():
    result = ToySpeck(3).analysis.find_minimax_xor_differential_trail(
        fixed_input_differences={"key": 1}, maximum_partition_weight=0
    )
    assert result.status == "unsatisfiable"
    assert not result.is_optimal and result.trail is None


def test_portable_backend_keeps_related_key_minimax_objective():
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
    result = ToySpeck(3).analysis.find_minimax_xor_differential_trail(
        fixed_input_differences={"key": 1}, solver=driver
    )
    assert result.status == "satisfiable"
    assert result.is_optimal and result.trail is not None
    assert result.trail.objective_weight == 2
