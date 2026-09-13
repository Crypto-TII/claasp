import shutil

import pytest

from claasp_next.ciphers import MiMCPermutation
from claasp_next.domains import PrimeField
from claasp_next.drivers.algebra import MsolveDriver, SingularDriver
from claasp_next.representations.constraints.polynomial import (
    Polynomial, PolynomialSystem, PrimeFieldPolynomialModel,
)
from claasp_next.representations.constraints.polynomial.exporters import MsolveExporter, SingularExporter


pytestmark = pytest.mark.external


@pytest.mark.skipif(shutil.which("Singular") is None, reason="Singular is not installed")
def test_singular_driver_executes_a_serialized_polynomial_artifact():
    system = PrimeFieldPolynomialModel(MiMCPermutation(17, 5, (1,))).polynomial_system()
    result = SingularDriver().execute(SingularExporter().export(system) + "print(size(I));\n")
    assert result.stdout.strip() == str(len(system.equations))


@pytest.mark.skipif(shutil.which("msolve") is None, reason="msolve is not installed")
def test_msolve_driver_executes_a_serialized_polynomial_artifact():
    field = PrimeField(65537)
    x = Polynomial.variable(field, "x")
    system = PolynomialSystem(field, ("x",), (x - 3,), ("fix x",))
    result = MsolveDriver().execute(MsolveExporter().export(system))
    assert result.result_text.strip()
