"""Optional Matplotlib rendering of retained trail search evidence."""


def _plot(result, *, show, save_to, details=False, value_format="hex"):
    from claasp.presentation._impossible import _is_impossible

    if _is_impossible(result):
        from claasp.drivers.renderers._impossible import _plot as impossible_plot

        return impossible_plot(
            result, details=details, value_format=value_format, show=show, save_to=save_to
        )
    if details or value_format != "hex":
        raise ValueError(
            "plot details and value_format are supported for impossible trail diagrams"
        )

    from claasp.drivers.renderers.presentation import FigureArtifact, _finish_figure, _matplotlib
    from claasp.presentation._search_results import _view
    from claasp.provenance import DriverIdentity, DriverKind

    view = _view(result)
    pyplot = _matplotlib()
    from textwrap import fill

    count = max(1, len(view.panels))
    title = "\n".join(fill(note, width=110) for note in (view.title, *view.notes) if note)
    height = max(3, count * 2.8) + 0.18 * len(title.splitlines())
    figure, axes = pyplot.subplots(count, 1, squeeze=False, figsize=(10, height))
    try:
        figure.suptitle(title, fontsize=10)
        series = []
        if not view.panels:
            axes[0, 0].text(0.5, 0.5, "No retained witness to display.", ha="center", va="center")
            axes[0, 0].set_axis_off()
        for index, panel in enumerate(view.panels):
            ax = axes[index, 0]
            positions = tuple(range(len(panel.labels)))
            for name, values in panel.series:
                discrete = panel.states or panel.xlabel == "Evidence" or "indicator" in panel.ylabel
                ax.plot(
                    positions, values, marker="o", linestyle="none" if discrete else "-", label=name
                )
                series.append((f"{panel.title}: {name}", values))
            ax.set(title=panel.title, xlabel=panel.xlabel, ylabel=panel.ylabel)
            ax.set_xticks(
                positions,
                panel.labels,
                rotation=45 if len(positions) > 8 else 0,
                ha="right" if len(positions) > 8 else "center",
            )
            if panel.states:
                ax.set_yticks(range(len(panel.states)), panel.states)
                ax.set_ylim(-0.25, len(panel.states) - 0.75)
            if "probability" in panel.ylabel.lower():
                ax.set_ylim(0, 1.05)
            if panel.ylabel == "Signed coefficient":
                ax.set_ylim(-1.05, 1.05)
            if panel.series:
                ax.legend()
            ax.grid(alpha=0.25)
        figure.tight_layout()
        _finish_figure(figure, show=show, save_to=save_to)
        return FigureArtifact(
            figure,
            "search_evidence",
            tuple(series),
            DriverIdentity("matplotlib", DriverKind.RENDERER),
        )
    except BaseException:
        pyplot.close(figure)
        raise
