import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from claasp import PrimeField
from claasp.primitives import MiMC
from claasp.representations.constraints.polynomial import (
    Polynomial,
    PolynomialSystem,
    PrimeFieldPolynomialModel,
)
from claasp.representations.constraints.polynomial.exporters import MsolveExporter


def test_msolve_export_is_deterministic_and_uses_ordered_variable_mapping():
    system = PrimeFieldPolynomialModel(MiMC(17, 3, (1,))).polynomial_system()
    exporter = MsolveExporter()

    first = exporter.export(system)

    assert first == exporter.export(system)
    assert first.splitlines()[:2] == ["x0,x1,x2,x3", "17"]
    assert first.count(",\n") == len(system.equations) - 1
    assert not first.endswith(",")


def test_msolve_export_rejects_unsupported_large_characteristic():
    field = PrimeField(2**61 - 1)
    x = Polynomial.variable(field, "x")
    system = PolynomialSystem(field, ("x",), (x,), ("test",))

    with pytest.raises(ValueError, match=r"smaller than 2\^31"):
        MsolveExporter().export(system)


@pytest.mark.skipif(shutil.which("msolve") is None, reason="msolve is not installed")
def test_exported_input_is_accepted_by_msolve():
    # msolve 0.6.5 can crash on tiny characteristics such as 17; use the
    # smallest Fermat prime above its practical 16-bit implementation range.
    field = PrimeField(65537)
    x = Polynomial.variable(field, "x")
    y = Polynomial.variable(field, "y")
    system = PolynomialSystem(
        field,
        ("x", "y"),
        (x - 3, y - x * x),
        ("fix x", "quadratic relation"),
    )

    with TemporaryDirectory() as directory:
        input_path = Path(directory) / "system.ms"
        output_path = Path(directory) / "result.ms"
        input_path.write_text(MsolveExporter().export(system), encoding="utf-8")
        subprocess.run(
            ["msolve", "-f", str(input_path), "-o", str(output_path)],
            text=True,
            capture_output=True,
            check=True,
        )
        assert output_path.read_text(encoding="utf-8").strip()
