import shutil
import subprocess

import pytest

from claasp_next.drivers.solvers import CPStatus, MiniZincSolver
from claasp_next.analysis import AnalysisProblem, FixedValue
from claasp_next.ciphers import SpeckBlockCipher
from claasp_next.representations.constraints.cp import MiniZincModel


pytestmark = pytest.mark.external


def _test_solver():
    listed = subprocess.run(
        ["minizinc", "--solvers"], text=True, capture_output=True, check=True
    ).stdout.lower()
    return "gecode" if "gecode" in listed else "coin-bc"


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
