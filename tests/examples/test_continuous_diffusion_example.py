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
    example = _script("continuous_diffusion")
    results = example.run_example(samples=4)
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
        views = example.plot_views(results[0])
        assert len(views) == 4
        assert views[1].kind == "continuous_diffusion_heatmap"
        image = pyplot.figure(views[1].figure).axes[0].images[0]
        assert image.get_clim() == (0, 2)
        assert image.get_array().tolist() == [list(row) for row in results[0].vectors]
        assert image.get_cmap()(0.5) == pytest.approx(pyplot.get_cmap("RdYlGn")(1.0))
        for artifact, expected_planes in zip(views[2:], (0, 8), strict=True):
            axis = pyplot.figure(artifact.figure).axes[0]
            assert axis.get_zlim() == (0, 2)
            planes = [
                item for item in axis.collections if type(item).__name__ == "Poly3DCollection"
            ]
            assert len(planes) == expected_planes
            assert all(plane.get_alpha() == 1 for plane in planes)
    finally:
        pyplot.close("all")
