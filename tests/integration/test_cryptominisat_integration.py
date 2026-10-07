import shutil

import pytest

from claasp.drivers.solvers import CryptoMiniSatSolver, SatStatus
from claasp.representations.constraints.sat import NativeXorCNFFormula

pytestmark = pytest.mark.external


def test_cryptominisat_solves_signed_native_xor_and_reports_version():
    assert shutil.which("cryptominisat5") is not None, (
        "the external test job must install CryptoMiniSat"
    )
    formula = NativeXorCNFFormula(("a", "b", "y"), (), (), (), ((1, 2, -3),), ("xor",))
    solver = CryptoMiniSatSolver(timeout_seconds=10)

    satisfiable = solver.solve(formula, {"a": 1, "b": 0, "y": 1})
    assert satisfiable.status is SatStatus.SATISFIABLE
    assert formula.is_satisfied(satisfiable.assignment or {})

    unsatisfiable = solver.solve(formula, {"a": 1, "b": 0, "y": 0})
    assert unsatisfiable.status is SatStatus.UNSATISFIABLE
    assert unsatisfiable.assignment is None
    assert solver.version() == "CryptoMiniSat version 5.11.15"
