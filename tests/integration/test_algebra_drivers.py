import shutil

import pytest

from claasp.domains import PrimeField
from claasp.drivers.algebra import MsolveDriver, SingularDriver
from claasp.primitives import MiMC
from claasp.representations.constraints.polynomial import (
    Polynomial,
    PolynomialSystem,
    PrimeFieldPolynomialModel,
)
from claasp.representations.constraints.polynomial.exporters import (
    MsolveExporter,
    SingularExporter,
)

pytestmark = pytest.mark.external


@pytest.mark.skipif(shutil.which("Singular") is None, reason="Singular is not installed")
def test_singular_driver_executes_a_serialized_polynomial_artifact():
    system = PrimeFieldPolynomialModel(MiMC(17, 5, (1,))).polynomial_system()
    result = SingularDriver().execute(SingularExporter().export(system) + "print(size(I));\n")
    assert result.stdout.strip() == str(len(system.equations))


@pytest.mark.skipif(shutil.which("msolve") is None, reason="msolve is not installed")
def test_msolve_driver_executes_a_serialized_polynomial_artifact():
    field = PrimeField(65537)
    x = Polynomial.variable(field, "x")
    system = PolynomialSystem(field, ("x",), (x - 3,), ("fix x",))
    result = MsolveDriver().execute(MsolveExporter().export(system))
    assert result.result_text.strip()
