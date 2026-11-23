import re
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
    assert re.fullmatch(r"CryptoMiniSat version 5\.11\.\d+", solver.version())


def test_native_xor_linear_enumeration_enforces_output_mask():
    from claasp.primitives import BitVectorSBox
    from claasp.representations.constraints.sat import WordXorLinearNativeXorSATModel

    p = BitVectorSBox(2, (0, 1, 2, 3))
    for mask, possible in ((0b01, True), (0b10, False)):
        model = WordXorLinearNativeXorSATModel(
            p, maximum_weight=0, fixed_input_masks={"input": 0b01}, output_mask=mask
        )
        result = model.enumerate_trails(
            CryptoMiniSatSolver(timeout_seconds=10), limit=8
        ).require_complete()
        assert len(result.trails) == int(possible)
        assert dict(result.reproducibility)["output_mask"] == repr(mask)
        for trail in result.trails:
            assert trail.output_mask == mask and model.check_characteristic(trail)
