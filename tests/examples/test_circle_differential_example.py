"""Exercise the downloadable circle-differential Basic example."""

import importlib.util
from io import StringIO
from math import log2
from pathlib import Path
from random import Random

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
    assert result.differences == (0x80000000, 0x01000100, 0x01020502)
    assert result.prefix_counts == (4096, 1042, 135)
    assert not result.evidence.complete and result.evidence.trials == 4096
    assert result.evidence.seed == 7 and not result.searched
    assert result.evidence.primitive_name == "speck"
    assert result.evidence.fixed_inputs == (("key", 0),)
    assert result.evidence.lower > 0

    # Independent two-round SPECK32/64 reference under the zero key. Both
    # round keys are zero; the full graph evaluation is not used by this oracle.
    def circle(x, y):
        correction = sum(
            (
                (
                    (((x >> (shift + 3)) & 1) & ((y >> (shift + 2)) & 1))
                    ^ (((x >> (shift + 2)) & 1) & ((y >> (shift + 3)) & 1))
                )
                << shift
            )
            for shift in range(0, 32, 4)
        )
        return x ^ y ^ correction

    def encrypt_round(value):
        x, y = value >> 16, value & 0xFFFF
        x = ((x >> 7) | (x << 9)) & 0xFFFF
        x = (x + y) & 0xFFFF
        y = (((y << 2) | (y >> 14)) & 0xFFFF) ^ x
        return (x << 16) | y

    counts = [4096, 0, 0]
    rng = Random(7)
    for _ in range(4096):
        x = rng.getrandbits(32)
        y = circle(x, result.differences[0])
        matches = True
        for i in (1, 2):
            x, y = encrypt_round(x), encrypt_round(y)
            matches = matches and circle(x, y) == result.differences[i]
            counts[i] += int(matches)
    assert tuple(counts) == result.prefix_counts
    stream = StringIO()
    result.to_terminal(file=stream)
    assert "0x80000000" in stream.getvalue() and "0x1020502" in stream.getvalue()
    assert "estimate" in stream.getvalue() and "95% confidence interval" in stream.getvalue()
    try:
        target = tmp_path / "example.png"
        artifact = result.plot(show=False, save_to=target)
        assert target.is_file()
        assert dict(artifact.series)["cumulative_weight"][-1] == pytest.approx(-log2(135 / 4096))
        assert "Estimated" in artifact.figure.axes[0].get_title()
    finally:
        pyplot.close("all")
