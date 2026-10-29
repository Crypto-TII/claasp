"""Optional plot layout for equation-variable incidence graphs."""


def plot_connection_graph(graph, *, show=True, save_to=None):
    """Plot the retained incidence data and return the Matplotlib figure.

    EXAMPLES::

        >>> callable(plot_connection_graph)
        True
    """
    import matplotlib.pyplot as plt

    if len(graph.variables) + len(graph.equations) > 2000:
        raise ValueError("select a round to plot at most 2000 graph nodes")
    figure, axis = plt.subplots(figsize=(8, 6))
    positions = {}
    for x, nodes in enumerate((graph.variables, graph.equations)):
        for index, node in enumerate(nodes):
            positions[node] = (x, index / max(1, len(nodes) - 1))
        axis.scatter(
            [x] * len(nodes),
            [positions[node][1] for node in nodes],
            s=12,
            label="Variables" if x == 0 else "Equations",
            zorder=2,
        )
    for source, target in graph.edges:
        a, b = positions[source], positions[target]
        axis.plot((a[0], b[0]), (a[1], b[1]), color="0.7", linewidth=0.4, zorder=1)
    if len(positions) <= 60:
        for name, (x, y) in positions.items():
            axis.annotate(name, (x, y), xytext=(4, 2), textcoords="offset points", fontsize=8)
    axis.set_axis_off()
    axis.legend()
    figure.tight_layout()
    if save_to is not None:
        figure.savefig(save_to)
    if show:
        plt.show()
    return figure
