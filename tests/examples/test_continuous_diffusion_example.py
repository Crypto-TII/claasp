"""Execute both downloadable continuous-diffusion scripts in presentation CI."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("mpmath")
pytest.importorskip("matplotlib").use("Agg")
pyplot = pytest.importorskip("matplotlib.pyplot")
ROOT = Path(__file__).resolve().parents[2] / "docs" / "examples"


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_basic_script_uses_actual_aes_defaults_and_reports(tmp_path):
    result = _script("basic_continuous_diffusion").run_example()
    try:
        result.to_terminal()
        artifact = result.plot(show=False, save_to=tmp_path / "caf.png")
        assert result.primitive_family == "aes"
        assert result.round_numbers == tuple(range(1, 11))
        assert len(result.samples[0]) == 16
        assert any(value > 0.5 for value in result.factors[4:])
        assert artifact.series == (("CAF", result.factors),)
        assert (tmp_path / "caf.png").read_bytes().startswith(b"\x89PNG")
    finally:
        pyplot.close("all")


def test_advanced_script_runs_all_experiments_and_plots():
    results = _script("continuous_diffusion").run_example(samples=4)
    try:
        assert [result.input_name for result in results] == [
            "plaintext",
            "plaintext",
            "key",
            "plaintext",
        ]
        assert results[1].lambda_value == 0.00001
        assert results[-1].method == "uniform_near_pairs"
        for result in results:
            result.to_terminal()
            result.plot(show=False)
            assert result.round_numbers == tuple(range(1, 9))
            assert all(0 <= value <= 2 for value in result.factors)
            assert pyplot.gcf().axes[0].get_ylabel() == "Continuous avalanche factor"
    finally:
        pyplot.close("all")
