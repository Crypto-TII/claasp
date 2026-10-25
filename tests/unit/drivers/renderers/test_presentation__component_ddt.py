"""DDT plots retain exact counts and use explicit display scales."""

import importlib

import pytest

from claasp.primitives import Present

pytest.importorskip("matplotlib").use("Agg")
pyplot = pytest.importorskip("matplotlib.pyplot")


def test_ddt_counts_probability_and_zero_row_reuse_retained_data(monkeypatch, tmp_path):
    ddt = Present(number_of_rounds=1).analysis.component("sbox").ddt()
    module = importlib.import_module("claasp.analysis.component_inspection")

    def forbidden(*args, **kwargs):
        raise AssertionError("plotting must not recompute the DDT")

    monkeypatch.setattr(module, "_rectangular_ddt", forbidden)
    try:
        count_plot = ddt.plot(show=False, save_to=tmp_path / "counts.png")
        assert count_plot.kind == "component_ddt"
        assert pyplot.figure(count_plot.figure).axes[0].images[0].get_array().tolist() == [
            list(row) for row in ddt.counts[1:]
        ]
        assert pyplot.figure(count_plot.figure).axes[0].images[0].get_clim() == (0, 4)
        probability = ddt.plot(show=False, scale="probability")
        assert pyplot.figure(probability.figure).axes[0].images[0].get_clim() == (0, 0.25)
        assert probability.series[0][1] == tuple(value / 16 for value in ddt.counts[1])
        full = ddt.plot(show=False, include_zero=True)
        assert pyplot.figure(full.figure).axes[0].images[0].get_array().shape == (16, 16)
        assert pyplot.figure(full.figure).axes[0].images[0].get_clim() == (0, 16)
        assert (tmp_path / "counts.png").read_bytes().startswith(b"\x89PNG")
        with pytest.raises(ValueError, match="scale"):
            ddt.plot(scale="wrong", show=False)
    finally:
        pyplot.close("all")
