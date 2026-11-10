"""Drivers fail before execution when a representation would lose constraints."""

import pytest

from claasp.drivers.solvers import (
    GLPKSolver,
    HighsSolver,
    KissatSolver,
    MinisatSolver,
    MiniZincSolver,
    Z3Solver,
)
from claasp.representations.constraints.sat import NativeXorCNFFormula


@pytest.mark.parametrize(
    "driver",
    (KissatSolver(), MinisatSolver(), Z3Solver(), GLPKSolver(), HighsSolver(), MiniZincSolver()),
)
def test_plain_solver_paths_reject_native_parity_before_executable_lookup(driver, monkeypatch):
    import shutil

    def forbidden(*args, **kwargs):
        raise AssertionError("a lossy representation must fail before execution")

    monkeypatch.setattr(shutil, "which", forbidden)
    native = NativeXorCNFFormula(("x",), ((-1,),), ("zero",), (), ((1,),), ("one",))
    with pytest.raises(TypeError, match="native XOR"):
        driver.solve(native)


def test_z3_incremental_rejects_native_parity_before_starting_a_process():
    native = NativeXorCNFFormula(("x",), (), (), (), ((1,),), ("one",))
    with pytest.raises(TypeError, match="native XOR"):
        with Z3Solver(executable="definitely-no-z3").incremental(native):
            raise AssertionError("session must not start")
