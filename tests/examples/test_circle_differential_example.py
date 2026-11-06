"""Exercise the downloadable circle-differential Basic example."""

import importlib.util
from io import StringIO
from pathlib import Path

import pytest


def test_basic_circle_differential_example(tmp_path):
    pytest.importorskip("matplotlib").use("Agg")
    from matplotlib import pyplot

    path = Path(__file__).resolve().parents[2] / "docs/examples/basic_circle_differential.py"
    spec = importlib.util.spec_from_file_location("basic_circle_differential", path)
    assert spec is not None and spec.loader is not None
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    result = example.run_example()
    assert result.differences == (7, 6) and result.probability == 1
    assert result.evidence.complete and result.evidence.trials == 16
    stream = StringIO()
    result.to_terminal(file=stream)
    assert "0x7" in stream.getvalue() and "0x6" in stream.getvalue()
    try:
        target = tmp_path / "example.png"
        result.plot(show=False, save_to=target)
        assert target.is_file()
    finally:
        pyplot.close("all")
