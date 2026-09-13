import shutil
import subprocess

import pytest

from claasp_next.drivers.solvers import CPStatus, MiniZincSolver
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
