"""Inheritance, storage and optional-import contracts for presentation mixins."""

from dataclasses import FrozenInstanceError, dataclass
from io import StringIO

import pytest

from claasp._result_presentation import PlotMixin, TerminalMixin


@dataclass(frozen=True, slots=True)
class ExampleResult(PlotMixin, TerminalMixin):
    value: int


def test_inherited_methods_forward_the_actual_receiver_and_options(monkeypatch, tmp_path):
    from claasp.drivers.renderers import _search_results as renderer
    from claasp.presentation import _search_results as presentation

    result = ExampleResult(7)
    figure = object()
    destination = tmp_path / "evidence.png"
    calls = []

    def plot(receiver, *, details, value_format, show, save_to):
        calls.append((receiver, show, save_to, details, value_format))
        return figure

    terminal_options = []

    def terminal(receiver, *, details, value_format, file):
        terminal_options.append((details, value_format))
        assert receiver is result
        print(receiver.value, file=file)

    monkeypatch.setattr(renderer, "_plot", plot)
    monkeypatch.setattr(presentation, "_to_terminal", terminal)
    assert result.plot(show=False, save_to=destination) is figure
    assert calls == [(result, False, destination, False, "hex")]
    assert calls[0][0] is result
    output = StringIO()
    assert result.to_terminal(file=output) is None
    assert output.getvalue() == "7\n"
    assert terminal_options == [(False, "hex")]
    result.to_terminal(details=True, value_format="binary", file=StringIO())
    assert terminal_options[-1] == (True, "binary")
    assert result.plot() is figure
    assert calls[-1] == (result, True, None, False, "hex")
    assert result.plot(details=True, value_format="binary", show=False) is figure
    assert calls[-1] == (result, False, None, True, "binary")


def test_mixins_preserve_slotted_frozen_dataclass_storage():
    result = ExampleResult(7)
    assert not hasattr(result, "__dict__")
    assert PlotMixin.__slots__ == TerminalMixin.__slots__ == ()
    field_name = "value"
    with pytest.raises(FrozenInstanceError):
        setattr(result, field_name, 8)
    assert result.value == 7


def test_specialized_terminal_report_overrides_shared_default(monkeypatch):
    from fractions import Fraction

    from claasp.analysis.quasidifferential import QuasidifferentialTrail
    from claasp.presentation import _search_results as presentation

    def forbidden(*args, **kwargs):
        pytest.fail("specialized terminal reports must retain their own implementation")

    monkeypatch.setattr(presentation, "_to_terminal", forbidden)
    result = QuasidifferentialTrail("example", {}, {}, 1, 0, (), Fraction(-1, 2))
    assert isinstance(result, PlotMixin)
    assert type(result).plot is PlotMixin.plot
    assert type(result).to_terminal is not TerminalMixin.to_terminal
    output = StringIO()
    result.to_terminal(file=output)
    assert "-1/2" in output.getvalue()
    assert "output mask" in output.getvalue()


def test_importing_mixins_does_not_import_optional_presentation_modules():
    import subprocess
    import sys

    script = """
import claasp
import sys
sys.modules.pop('claasp._result_presentation', None)
sys.modules['matplotlib'] = None
sys.modules['claasp.presentation'] = None
sys.modules['claasp.drivers.renderers._search_results'] = None
from claasp._result_presentation import PlotMixin, TerminalMixin
class Result(PlotMixin, TerminalMixin):
    __slots__ = ()
result = Result()
assert not hasattr(result, '__dict__')
assert 'matplotlib.pyplot' not in sys.modules
"""
    subprocess.run([sys.executable, "-c", script], check=True)


def test_impossible_mixins_forward_key_visibility_and_notation(monkeypatch, tmp_path):
    from claasp._result_presentation import ImpossiblePlotMixin, ImpossibleTerminalMixin
    from claasp.drivers.renderers import _impossible as renderer
    from claasp.presentation import _impossible as presentation

    @dataclass(frozen=True, slots=True)
    class ImpossibleExample(ImpossibleTerminalMixin, ImpossiblePlotMixin):
        value: int

    result = ImpossibleExample(1)
    calls = []
    artifact = object()

    def plot(receiver, **options):
        assert receiver is result
        calls.append(options)
        return artifact

    def terminal(receiver, **options):
        assert receiver is result
        calls.append(options)

    monkeypatch.setattr(renderer, "_plot", plot)
    monkeypatch.setattr(presentation, "_to_terminal", terminal)
    assert not hasattr(result, "__dict__")
    assert ImpossibleTerminalMixin.__slots__ == ImpossiblePlotMixin.__slots__ == ()
    result.to_terminal()
    assert calls[-1] == dict(details=False, value_format="binary", include_key=False, file=None)
    stream = StringIO()
    result.to_terminal(details=True, value_format="dot_one", include_key=True, file=stream)
    assert calls[-1] == dict(details=True, value_format="dot_one", include_key=True, file=stream)
    assert result.plot(show=False) is artifact
    assert calls[-1] == dict(
        details=False, value_format="hex", include_key=False, show=False, save_to=None
    )
    destination = tmp_path / "impossible.png"
    assert (
        result.plot(
            details=True, value_format="dot_one", include_key=True, show=False, save_to=destination
        )
        is artifact
    )
    assert calls[-1] == dict(
        details=True, value_format="dot_one", include_key=True, show=False, save_to=destination
    )
