"""Exercise the exact script used by the user guide, including its figures."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("matplotlib").use("Agg")
plt = pytest.importorskip("matplotlib.pyplot")

SCRIPT = Path(__file__).resolve().parents[2] / "docs" / "examples" / "avalanche.py"
spec = importlib.util.spec_from_file_location("avalanche_example", SCRIPT)
assert spec is not None and spec.loader is not None
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


def test_documentation_example_renders_all_views(tmp_path):
    try:
        results, figures = example.run_example(
            speck_rounds=2, speck_samples=2, chacha_rounds=2, chacha_samples=2
        )
        assert [len(result.round_numbers) for result in results] == [2, 2, 2]
        assert [result.input_bit_count for result in results] == [32, 64, 512]
        assert [result.output_bit_count for result in results] == [32, 32, 512]
        assert len(figures) == 8
        for result in results:
            for matrix in result.round_probabilities:
                assert all(0 <= value <= 1 for row in matrix for value in row)
        for index, figure in enumerate(figures):
            path = tmp_path / f"avalanche-{index}.png"
            figure.savefig(path)
            assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert figures[0].axes[0].get_xlabel() == "Rounds"
        for figure in figures[2:4]:
            image = figure.axes[0].images[0]
            assert image.get_clim() == (0, 1)
            assert image.get_cmap().name == "RdYlGn"
        for index, figure in enumerate(figures[4:], start=4):
            assert figure.axes[0].get_zlim() == (0, 1)
            planes = [
                collection
                for collection in figure.axes[0].collections
                if type(collection).__name__ == "Poly3DCollection"
            ]
            assert len(planes) == (2 if index in (5, 7) else 0)
            assert all(plane.get_alpha() == 1 for plane in planes)
            if index in (4, 6):
                assert len(figure.axes[0].lines) == 2
    finally:
        plt.close("all")


def test_basic_script_runs_with_its_documented_defaults(capsys):
    basic_spec = importlib.util.spec_from_file_location(
        "basic_avalanche", SCRIPT.with_name("basic_avalanche.py")
    )
    assert basic_spec is not None and basic_spec.loader is not None
    basic = importlib.util.module_from_spec(basic_spec)
    basic_spec.loader.exec_module(basic)
    result = basic.run_example()
    try:
        result.to_terminal()
        artifact = result.plot(show=False)
        assert result.sample_count == 1000
        assert result.round_numbers == tuple(range(1, 8))
        assert result.metric == "probability"
        assert result.method == "numpy_paired_evaluation"
        assert "avalanche_probability" in capsys.readouterr().out
        assert artifact.figure.axes[0].get_ylabel() == "Avalanche probability"
    finally:
        plt.close("all")
