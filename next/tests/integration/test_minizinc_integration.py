import shutil
import subprocess

import pytest

from claasp_next.drivers.solvers import CPStatus, MiniZincSolver
from claasp_next.analysis import AnalysisProblem, FixedValue
from claasp_next.ciphers import SpeckBlockCipher
from claasp_next.representations.constraints.cp import MiniZincModel
from claasp_next.semantics import (
    DETERMINISTIC_TRUNCATED_XOR,
    XOR_DIFFERENTIAL,
    XOR_LINEAR,
)
from claasp_next.semantics.cryptanalysis import PropagationProblem
from claasp_next.representations.constraints.cp import (
    PresentDifferentialCPModel,
    PresentLinearCPModel,
    SBoxDifferenceCPModel,
    SpeckDifferentialCPModel,
    SpeckTruncatedCPModel,
)
from claasp_next.semantics.cryptanalysis import TruncatedXorDifference
from claasp_next.representations.constraints.smt.trails import (
    check_present_linear_smt_trail,
    check_present_smt_trail,
)
from claasp_next.ciphers import PresentBlockCipher


pytestmark = pytest.mark.external


def _test_solver():
    listed = subprocess.run(
        ["minizinc", "--solvers"], text=True, capture_output=True, check=True
    ).stdout.lower()
    for solver in ("chuffed", "gecode", "cp-sat", "coin-bc"):
        if solver in listed:
            return solver
    raise AssertionError("the external test job must provide a MiniZinc solver")


def test_minizinc_solves_and_projects_named_values():
    assert shutil.which("minizinc") is not None, "the external test job must install MiniZinc"
    model = MiniZincModel(
        declarations=("var 0..3: x;", "array[1..3] of var 0..1: bits;"),
        constraints=(
            "constraint x = 2;",
            "constraint bits = [1, 0, 1];",
        ),
        provenance=("portable CP foundation fixture",),
    )

    result = MiniZincSolver(solver=_test_solver()).solve(model)

    assert result.status is CPStatus.SATISFIED
    assert result.values == {"x": 2, "bits": [1, 0, 1]}
    assert result.runtime_seconds >= 0


def test_minizinc_reports_unsatisfiable_models():
    model = MiniZincModel(
        declarations=("var 0..1: x;",),
        constraints=("constraint x = 0;", "constraint x = 1;"),
    )

    result = MiniZincSolver(solver=_test_solver()).solve(model)

    assert result.status is CPStatus.UNSATISFIABLE
    assert result.values is None


def test_minizinc_recovers_and_independently_verifies_reduced_speck_key():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    plaintext = 0x6574694C
    ciphertext = cipher.evaluate(plaintext, 0x1918111009080100)

    result = cipher.analyze().recover_input(
        "key",
        known_inputs={"plaintext": plaintext},
        output=ciphertext,
        solver=MiniZincSolver(solver=_test_solver(), timeout_seconds=30),
    )

    assert result.is_satisfiable
    assert cipher.evaluate(plaintext, result.value("key")) == ciphertext


def test_minizinc_reproduces_legacy_full_speck_missing_bits_result():
    cipher = SpeckBlockCipher(number_of_rounds=22)
    problem = AnalysisProblem(
        cipher,
        (
            FixedValue(cipher.input("plaintext"), 0x6574694C),
            FixedValue(cipher.input("key"), 0x1918111009080100),
        ),
        {"ciphertext": cipher.output},
    )

    result = cipher.analyze().solve(
        problem,
        MiniZincSolver(solver=_test_solver(), timeout_seconds=60),
    )

    assert result.is_satisfiable
    assert result.value("ciphertext") == 0xA86842F2
    assert cipher.evaluate(0x6574694C, 0x1918111009080100) == result.value("ciphertext")


def test_minizinc_proves_present_two_round_differential_optimum():
    cipher = PresentBlockCipher(number_of_rounds=2)
    solver = MiniZincSolver(solver=_test_solver(), timeout_seconds=60)
    below = PresentDifferentialCPModel(PropagationProblem(
        cipher,
        XOR_DIFFERENTIAL,
        maximum_weight=3,
        provenance=("PRESENT-2 legacy lower bound",),
    ))
    optimum = PresentDifferentialCPModel(PropagationProblem(
        cipher,
        XOR_DIFFERENTIAL,
        maximum_weight=4,
        provenance=("PRESENT-2 legacy optimum",),
    ))

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 4
    assert check_present_smt_trail(cipher, trail)


def test_minizinc_proves_present_three_round_linear_optimum_with_signs():
    cipher = PresentBlockCipher(number_of_rounds=3)
    solver = MiniZincSolver(solver=_test_solver(), timeout_seconds=60)
    below = PresentLinearCPModel(PropagationProblem(
        cipher,
        XOR_LINEAR,
        maximum_weight=3,
        provenance=("PRESENT-3 legacy linear lower bound",),
    ))
    optimum = PresentLinearCPModel(PropagationProblem(
        cipher,
        XOR_LINEAR,
        maximum_weight=4,
        provenance=("PRESENT-3 legacy linear optimum",),
    ))

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 4
    assert all(step.transition.sign in (-1, 1) for step in trail.steps)
    assert check_present_linear_smt_trail(cipher, trail)


def test_minizinc_reproduces_legacy_speck_truncated_round_fixture():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    model = SpeckTruncatedCPModel(
        PropagationProblem(
            cipher,
            DETERMINISTIC_TRUNCATED_XOR,
            provenance=("legacy Speck deterministic-truncated fixture",),
        ),
        TruncatedXorDifference.parse("00000000011111001110000000000000"),
    )

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    output = model.decode_output(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert str(output) == "????100000000000????100000000011"


def test_minizinc_proves_impossible_and_possible_present_sbox_pairs():
    cipher = PresentBlockCipher(number_of_rounds=1)
    problem = PropagationProblem(
        cipher,
        XOR_DIFFERENTIAL,
        provenance=("exhaustive PRESENT S-box DDT",),
    )
    impossible = SBoxDifferenceCPModel(problem, "sbox_1_0", 1, 1)
    possible = SBoxDifferenceCPModel(problem, "sbox_1_0", 1, 3)
    solver = MiniZincSolver(solver=_test_solver())

    assert solver.solve(impossible.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(possible.cp_model())
    transition = problem.provider_for(possible.component).transition((1,), 3)

    assert solved.status is CPStatus.SATISFIED
    assert transition.is_possible
    assert transition.weight == 2


def test_minizinc_proves_legacy_speck_five_round_differential_optimum():
    cipher = SpeckBlockCipher(number_of_rounds=5)
    solver = MiniZincSolver(solver=_test_solver(), timeout_seconds=120)
    below = SpeckDifferentialCPModel(PropagationProblem(
        cipher, XOR_DIFFERENTIAL, maximum_weight=8,
        provenance=("legacy Speck32/64-5 lower bound",),
    ))
    optimum = SpeckDifferentialCPModel(PropagationProblem(
        cipher, XOR_DIFFERENTIAL, maximum_weight=9,
        provenance=("legacy Speck32/64-5 optimum",),
    ))

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 9
    assert len(trail.steps) == 5
