import pytest

from claasp.primitives import BitVectorSBox


def test_incidence_plot_returns_and_saves_the_retained_graph(tmp_path):
    matplotlib = pytest.importorskip("matplotlib")
    matplotlib.use("Agg")
    graph = BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system().connection_graph()
    figure = graph.plot(show=False, save_to=tmp_path / "graph.png")
    assert (tmp_path / "graph.png").stat().st_size > 0
    assert len(figure.axes[0].lines) == len(graph.edges)
