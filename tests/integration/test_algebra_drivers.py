import shutil

import pytest

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
from claasp.unit_types import PrimeField

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


@pytest.mark.skipif(shutil.which("Singular") is None, reason="Singular is not installed")
def test_boolean_ideal_basis_detects_inconsistent_fixed_io():
    from claasp.primitives import BitVectorSBox

    result = BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system()
    # Input 00 must map to output 00. Fix an inconsistent output bit.
    fixed = {name: 0 for _, names in result.system.inputs for name in names}
    output_variable = result.system.outputs[0].monomials[0].variables[0]
    impossible = result.groebner(
        fixed_variables={**fixed, output_variable: 1}, timeout_seconds=10
    ).require_complete()
    assert impossible.basis == ("1",)
    consistent = result.groebner(fixed_variables=fixed, timeout_seconds=10).require_complete()
    assert consistent.basis and consistent.basis != ("1",)
