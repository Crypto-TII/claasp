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
        assert len(figures) == 5
        for result in results:
            for matrix in result.round_probabilities:
                assert all(0 <= value <= 1 for row in matrix for value in row)
        for index, figure in enumerate(figures):
            path = tmp_path / f"avalanche-{index}.png"
            figure.savefig(path)
            assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert figures[0].axes[0].get_xlabel() == "Rounds"
        for figure in figures[1:3]:
            image = figure.axes[0].images[0]
            assert image.get_clim() == (0, 1)
            assert image.get_cmap().name == "RdYlGn"
        for figure in figures[3:]:
            assert figure.axes[0].get_zlim() == (0, 1)
            planes = [
                collection
                for collection in figure.axes[0].collections
                if type(collection).__name__ == "Poly3DCollection"
            ]
            assert len(planes) == 2
            assert all(plane.get_alpha() == 1 for plane in planes)
    finally:
        plt.close("all")
