import shutil
import subprocess

import pytest

from claasp.analysis.component_properties import (
    ComponentProperty,
    PropertyDomain,
    PropertyRequest,
)
from claasp.components import LinearMap
from claasp.domains import Bit
from claasp.drivers.analysis import MiniZincBranchNumberDriver
from claasp.graph import Port, ValueType

pytestmark = pytest.mark.external


def _solver():
    assert shutil.which("minizinc") is not None, "external job must install MiniZinc"
    available = subprocess.run(
        ["minizinc", "--solvers"], text=True, capture_output=True, check=True
    ).stdout.lower()
    for solver in ("chuffed", "gecode", "cp-sat", "coin-bc"):
        if solver in available:
            return solver
    raise AssertionError("external job must provide a MiniZinc solver")


def test_minizinc_driver_proves_asymmetric_differential_and_linear_branches():
    matrix = (
        (0, 0, 0, 1),
        (0, 1, 1, 0),
        (1, 0, 1, 0),
        (1, 1, 1, 1),
    )
    component = LinearMap(Port("x", ValueType(Bit(), (4,))), matrix)
    driver = MiniZincBranchNumberDriver(solver=_solver(), timeout_seconds=10)

    differential = driver.analyze(
        component,
        PropertyRequest(ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.BIT_LINEAR),
    )
    linear = driver.analyze(
        component,
        PropertyRequest(ComponentProperty.LINEAR_BRANCH_NUMBER, PropertyDomain.BIT_LINEAR),
    )

    assert differential.value == 3
    assert linear.value == 2
    assert differential.complete and linear.complete
