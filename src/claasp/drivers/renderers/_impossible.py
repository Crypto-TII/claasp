"""A full vertical impossible-trail diagram with a duplicated meeting state."""


def _plot(result, *, details, value_format, show, save_to):
    from claasp.drivers.renderers.presentation import FigureArtifact, _finish_figure, _matplotlib
    from claasp.presentation._impossible import _boundary, _groups, _notes, _pattern, _values
    from claasp.presentation._trail_values import _validate_value_format
    from claasp.provenance import DriverIdentity, DriverKind

    _validate_value_format(value_format)
    groups = _groups(result, details=details)
    pyplot = _matplotlib()
    import numpy as np
    from matplotlib.colors import BoundaryNorm, ListedColormap

    heights = [max(3, len(rows) * 0.38) for _, _, rows in groups] or [3]
    figure, axes = pyplot.subplots(
        max(1, len(groups)),
        1,
        squeeze=False,
        figsize=(13, sum(heights) + 1.8),
        gridspec_kw={"height_ratios": heights},
    )
    try:
        figure.suptitle("Impossible differential trail\n" + "\n".join(_notes(result)), fontsize=9)
        series = []
        if not groups:
            axes[0, 0].text(0.5, 0.5, "No retained witness to display.", ha="center")
            axes[0, 0].set_axis_off()
        for index, (title, trail, rows) in enumerate(groups):
            axis = axes[index, 0]
            _, _, positions, wordwise = _boundary(trail)
            states = ("zero", "known", "nonzero", "?") if wordwise else ("0", "1", "?")
            values = [_values(row.pattern) for row in rows]
            width = max(map(len, values), default=1)
            matrix = np.full((len(rows), width), np.nan)
            for row_number, (row, numbers) in enumerate(zip(rows, values)):
                matrix[row_number, : len(numbers)] = numbers
                label = f"{title}: {row.direction} {row.boundary} {row.source}"
                series.append((label, numbers))
                if row.contradictions:
                    axis.scatter(
                        row.contradictions,
                        [row_number] * len(row.contradictions),
                        marker="x",
                        s=55,
                        color="red",
                        linewidths=2,
                        zorder=3,
                    )
            cmap = ListedColormap(
                ("#eeeeee", "#67a9cf", "#fdae61", "#b2abd2")
                if wordwise
                else ("#eeeeee", "#67a9cf", "#b2abd2")
            )
            image = axis.imshow(
                matrix,
                interpolation="nearest",
                aspect="auto",
                cmap=cmap,
                norm=BoundaryNorm(tuple(i - 0.5 for i in range(len(states) + 1)), len(states)),
            )
            axis.set_yticks(
                range(len(rows)), [f"{row.direction} {row.boundary} {row.source}" for row in rows]
            )
            axis.set_xlabel("Word position" if wordwise else "Bit position (MSB first)")
            axis.set_ylabel("Original graph boundary / retained component")
            axis.set_title(title)
            if wordwise and width <= 32:
                for row_number, row in enumerate(rows):
                    text = _pattern(row.pattern, value_format=value_format)[1:-1].split(", ")
                    for position, label in enumerate(text):
                        axis.text(position, row_number, label, ha="center", va="center", fontsize=7)
            colorbar = figure.colorbar(image, ax=axis, ticks=range(len(states)), pad=0.02)
            colorbar.ax.set_yticklabels(states)
            indicator = tuple(
                float(i in positions) for i in range(len(_values(_boundary(trail)[0])))
            )
            series.append((f"{title}: contradiction positions", indicator))
        figure.tight_layout(rect=(0, 0, 1, 0.91))
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
