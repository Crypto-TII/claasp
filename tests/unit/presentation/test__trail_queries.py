"""Rendering retained results is dependency-free and does not rerun solvers."""

from importlib import import_module
from io import StringIO

import pytest


@pytest.mark.parametrize(
    "module,kind",
    [
        ("word_linear", "Linear"),
        ("word_differential", "Differential"),
        ("trails", "Linear"),
        ("trails", "Differential"),
    ],
)
def test_reports_preserve_completion_weights_boundaries_and_linear_sign(module, kind):
    module = import_module(f"claasp.representations.constraints.smt.{module}")
    characteristic = getattr(module, f"Word{kind}Characteristic")
    enumeration = getattr(module, f"Word{kind}Enumeration")
    args = (("plaintext", 1),), 2, ()
    trail = characteristic(*args, -1, ()) if kind == "Linear" else characteristic(*args, ())
    result = enumeration((trail,), False, 0.25)
    stream = StringIO()
    result.to_terminal(file=stream)
    text = stream.getvalue()
    assert "Incomplete enumeration" in text and "0x1" in text and "0x2" in text
    assert "0.250000" in text and "Index" in text
    assert ("Sign" in text and "-1" in text) if kind == "Linear" else "Sign" not in text
    assert "components" not in text
    stream = StringIO()
    result.to_terminal(details=True, file=stream)
    assert "Characteristic 0 components" in stream.getvalue()
    stream = StringIO()
    trail.to_terminal(file=stream)
    assert "no optimality claim" in stream.getvalue()
    assert "0x1" in stream.getvalue() and "0x2" in stream.getvalue()
