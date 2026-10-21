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


def test_profiles_preserve_entropy_before_averaging():
    from claasp.analysis.avalanche import AvalancheResult

    result = AvalancheResult("fixture", "input", 2, 9, ((0.0, 0.5), (1.0, 0.5)))
    assert example.output_profile(result) == (0.5, 0.5)
    assert example.output_profile(result, entropy=True) == (0.0, 1.0)


def test_round_prefix_matches_independent_paired_evaluations():
    from random import Random

    from claasp.primitives import Speck

    results = example.round_results(Speck, "plaintext", 2, 2)
    for rounds, result in enumerate(results, start=1):
        primitive = Speck(number_of_rounds=rounds)
        random = Random(9)
        pairs = [(random.getrandbits(32), random.getrandbits(64)) for _ in range(2)]
        expected = []
        for bit in range(32):
            differences = []
            for plaintext, key in pairs:
                baseline = primitive.evaluate(plaintext, key)
                changed = primitive.evaluate(plaintext ^ (1 << (31 - bit)), key)
                assert isinstance(baseline, int) and isinstance(changed, int)
                differences.append(baseline ^ changed)
            expected.append(
                tuple(sum((d >> (31 - b)) & 1 for d in differences) / 2 for b in range(32))
            )
        assert result.probabilities == tuple(expected)
        assert result.seed == 9
        assert result.sample_count == 2
        assert result.complete is False


def test_documentation_example_renders_all_views(tmp_path):
    try:
        results, figures = example.run_example(
            speck_rounds=2, speck_samples=2, chacha_rounds=2, chacha_samples=2
        )
        assert [len(group) for group in results] == [2, 2, 2]
        assert [group[0].input_bit_count for group in results] == [32, 64, 512]
        assert [group[0].output_bit_count for group in results] == [32, 32, 512]
        assert len(figures) == 4
        for group in results:
            for result in group:
                assert all(0 <= value <= 1 for row in result.probabilities for value in row)
        for index, figure in enumerate(figures):
            path = tmp_path / f"avalanche-{index}.png"
            figure.savefig(path)
            assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert figures[0].axes[0].images[0].get_clim() == (0, 1)
        assert figures[2].axes[0].get_zlim() == (0, 1)
        for figure in figures[:2]:
            assert figure.axes[0].images[0].get_cmap().name == "RdYlGn"
        for figure, group in zip(figures[2:], (results[0], results[2]), strict=True):
            points = figure.axes[0].collections[0]
            assert points.get_clim() == (0, 1)
            assert points.to_rgba(0.0) == (1.0, 0.0, 0.0, 1.0)
            assert points.to_rgba(0.5) == (0.0, 1.0, 0.0, 1.0)
            assert points.to_rgba(1.0) == (1.0, 0.0, 0.0, 1.0)
            assert points.to_rgba(0.25) == points.to_rgba(0.75)
            assert list(points.get_array()) == [
                value for result in group for value in example.output_profile(result)
            ]
    finally:
        plt.close("all")
