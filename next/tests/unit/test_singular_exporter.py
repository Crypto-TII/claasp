import shutil
import subprocess

import pytest

from claasp_next.ciphers import MiMCPermutation
from claasp_next.polynomial import PowerLoweringPolicy, PrimeFieldPolynomialModel
from claasp_next.polynomial.exporters import SingularExporter


def test_singular_export_is_deterministic_and_preserves_variable_mapping():
    system = PrimeFieldPolynomialModel(MiMCPermutation(17, 3, (1,))).polynomial_system()
    exporter = SingularExporter()

    first = exporter.export(system)
    second = exporter.export(system)

    assert first == second
    assert "// x0 = state_0" in first
    assert "ring r = 17,(x0,x1,x2,x3),dp;" in first
    assert "ideal I =" in first


def test_singular_export_validates_external_identifiers():
    system = PrimeFieldPolynomialModel(MiMCPermutation(17, 3, (1,))).polynomial_system()

    with pytest.raises(ValueError, match="ring_name"):
        SingularExporter().export(system, ring_name="invalid-name")


@pytest.mark.skipif(shutil.which("Singular") is None, reason="Singular is not installed")
def test_exported_program_is_accepted_by_singular():
    system = PrimeFieldPolynomialModel(
        MiMCPermutation(17, 5, (1,)), PowerLoweringPolicy.BINARY_CHAIN
    ).polynomial_system()
    program = SingularExporter().export(system) + 'print(size(I));\n'

    completed = subprocess.run(
        ["Singular", "--no-tty", "--quiet"],
        input=program,
        text=True,
        capture_output=True,
        check=True,
    )

    assert completed.stdout.strip() == str(len(system.equations))
