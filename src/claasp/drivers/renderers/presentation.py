"""Optional Matplotlib rendering for immutable typed presentation inputs.

Matplotlib is imported only inside rendering methods. Importing this module or
the core :mod:`claasp.presentation` package remains dependency-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import pi
from pathlib import Path

from claasp.analysis.avalanche import AvalancheResult
from claasp.analysis.component_properties import (
    PropertyClaim,
    PropertyDomain,
)
from claasp.analysis.statistical_results import (
    StatisticalTestRun,
)
from claasp.presentation.contracts import EvidenceClass
from claasp.provenance import DriverIdentity, DriverKind


class NormalizationDirection(str, Enum):
    """Meaning of increasing values on a normalized comparison axis.

    EXAMPLES::

        >>> tuple(member.value for member in NormalizationDirection)
        ('higher_is_better', 'lower_is_better')
    """

    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


@dataclass(frozen=True, slots=True)
class RadarScale:
    """Explicit normalization for one property in one mathematical domain.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (RadarScale.__dataclass_params__.frozen, tuple(field.name for field in fields(RadarScale)))
        (True, ('property', 'domain', 'minimum', 'maximum', 'direction', 'label'))
    """

    property: str
    domain: PropertyDomain
    minimum: float
    maximum: float
    direction: NormalizationDirection
    label: str

    def __post_init__(self) -> None:
        if not isinstance(self.domain, PropertyDomain):
            object.__setattr__(self, "domain", PropertyDomain(self.domain))
        if not isinstance(self.direction, NormalizationDirection):
            object.__setattr__(self, "direction", NormalizationDirection(self.direction))
        if not self.property or not self.label:
            raise ValueError("radar property and label must not be empty")
        if self.minimum >= self.maximum:
            raise ValueError("radar scale minimum must be less than maximum")


@dataclass(frozen=True, slots=True)
class RadarPoint:
    """One normalized property and the evidence retained behind it."""

    property: str
    original_value: float
    normalized_value: float
    evidence: EvidenceClass
    scale: RadarScale


@dataclass(frozen=True, slots=True)
class FigureArtifact:
    """An optional figure plus deterministic series data and renderer identity.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (FigureArtifact.__dataclass_params__.frozen, tuple(field.name for field in fields(FigureArtifact)))
        (True, ('figure', 'kind', 'series', 'driver', 'normalization', 'omitted'))
    """

    figure: object
    kind: str
    series: tuple[tuple[str, tuple[float, ...]], ...]
    driver: DriverIdentity
    normalization: tuple[RadarScale, ...] = ()
    omitted: tuple[str, ...] = ()


def _matplotlib():
    try:
        from matplotlib import pyplot
    except ImportError as error:  # pragma: no cover - depends on optional environment
        raise ImportError(
            "Matplotlib rendering requires the optional 'presentation' dependency"
        ) from error
    return pyplot


def _report(value):
    return value.report if isinstance(value, StatisticalTestRun) else value


class MatplotlibPresentationDriver:
    """Explicit optional renderer for radar, avalanche, and statistical views."""

    identity = DriverIdentity("matplotlib_presentation", DriverKind.RENDERER)

    def component_radar(self, label, results, scales) -> FigureArtifact:
        """Render only comparable properties with caller-supplied typed scales."""

        pyplot = _matplotlib()
        scale_map = {(scale.property, scale.domain): scale for scale in scales}
        if len(scale_map) != len(scales):
            raise ValueError("radar scales must be unique by property and domain")
        points = []
        omitted = []
        for result in results:
            key = (result.request.property.value, result.request.domain)
            if result.claim is PropertyClaim.UNAVAILABLE:
                omitted.append(f"{key[0]}:unavailable")
                continue
            scale = scale_map.get(key)
            if scale is None:
                omitted.append(f"{key[0]}:no_normalization")
                continue
            if isinstance(result.value, bool):
                value = float(result.value)
            elif isinstance(result.value, (int, float)):
                value = float(result.value)
            else:
                omitted.append(f"{key[0]}:incomparable_value")
                continue
            if not scale.minimum <= value <= scale.maximum:
                raise ValueError(f"{scale.property} value lies outside its declared radar scale")
            normalized = (value - scale.minimum) / (scale.maximum - scale.minimum)
            if scale.direction is NormalizationDirection.LOWER_IS_BETTER:
                normalized = 1.0 - normalized
            evidence = {
                PropertyClaim.EXACT: EvidenceClass.EXACT,
                PropertyClaim.PROVED_LOWER_BOUND: EvidenceClass.PROVED_BOUND,
                PropertyClaim.PROVED_UPPER_BOUND: EvidenceClass.PROVED_BOUND,
                PropertyClaim.EMPIRICAL: EvidenceClass.EMPIRICAL,
            }[result.claim]
            points.append(RadarPoint(key[0], value, normalized, evidence, scale))
        if len(points) < 3:
            raise ValueError(
                "a radar chart requires at least three comparable applicable properties"
            )
        angles = tuple(2 * pi * index / len(points) for index in range(len(points)))
        values = tuple(point.normalized_value for point in points)
        figure, axis = pyplot.subplots(subplot_kw={"projection": "polar"})
        axis.plot(angles + angles[:1], values + values[:1], marker="o", label=label)
        axis.fill(angles + angles[:1], values + values[:1], alpha=0.12)
        axis.set_xticks(angles)
        axis.set_xticklabels(
            tuple(
                f"{point.scale.label}\n{point.scale.direction.value}\n[{point.scale.minimum:g}, {point.scale.maximum:g}]\n{point.evidence.value}"
                for point in points
            )
        )
        axis.set_ylim(0.0, 1.0)
        axis.set_ylabel("normalized desirability (0 worst, 1 best)")
        axis.legend()
        return FigureArtifact(
            figure,
            "component_radar",
            ((label, values),),
            self.identity,
            tuple(point.scale for point in points),
            tuple(omitted),
        )

    def avalanche_matrix(self, result: AvalancheResult) -> FigureArtifact:
        """Render an empirical input-bit by output-bit probability matrix."""

        pyplot = _matplotlib()
        figure, axis = pyplot.subplots()
        colors = _avalanche_colors("probability")
        image = axis.imshow(result.probabilities, vmin=0.0, vmax=1.0, aspect="auto", cmap=colors)
        axis.set_xlabel("output bit (MSB first)")
        axis.set_ylabel("input bit (MSB first)")
        axis.set_title(
            f"{result.primitive_family} avalanche; n={result.sample_count}; seed={result.seed}; empirical"
        )
        figure.colorbar(image, ax=axis, label="observed flip probability (ideal 0.5)")
        return FigureArtifact(
            figure,
            "avalanche_matrix",
            tuple(
                (f"input_bit_{index}", tuple(row)) for index, row in enumerate(result.probabilities)
            ),
            self.identity,
        )

    def dieharder_assessments(self, result) -> FigureArtifact:
        """Render ordered Dieharder categories without hiding weak rows."""

        pyplot = _matplotlib()
        report = _report(result)
        mapping = {"failed": -1.0, "weak": 0.0, "passed": 1.0}
        values = tuple(mapping[item.assessment.value] for item in report.observations)
        labels = tuple(item.test_name for item in report.observations)
        figure, axis = pyplot.subplots()
        axis.scatter(tuple(range(len(values))), values, label="empirical assessment")
        axis.set_xticks(tuple(range(len(values))), labels, rotation=45, ha="right")
        axis.set_yticks((-1, 0, 1), ("failed", "weak", "passed"))
        axis.set_xlabel("test")
        axis.set_ylabel("assessment")
        axis.legend()
        return FigureArtifact(
            figure, "dieharder_assessments", (("assessment", values),), self.identity
        )

    def nist_proportions(self, result) -> FigureArtifact:
        """Render available NIST proportions and explicitly omit unavailable rows."""

        pyplot = _matplotlib()
        report = _report(result)
        available = tuple(row for row in report.rows if row.total_sequences)
        omitted = tuple(row.test_name for row in report.rows if not row.total_sequences)
        values = tuple(row.proportion for row in available)
        labels = tuple(row.test_name for row in available)
        figure, axis = pyplot.subplots()
        axis.scatter(tuple(range(len(values))), values, label="empirical pass proportion")
        axis.set_xticks(tuple(range(len(values))), labels, rotation=45, ha="right")
        axis.set_ylim(0.0, 1.0)
        axis.set_xlabel("test")
        axis.set_ylabel("passing proportion")
        axis.legend()
        return FigureArtifact(
            figure,
            "nist_proportions",
            (("pass_proportion", values),),
            self.identity,
            omitted=omitted,
        )


def _finish_figure(figure, *, show, save_to):
    """Keep figure display and file output inside the optional renderer."""
    if save_to is not None:
        figure.savefig(save_to)
    if show:
        _matplotlib().show()


def _plot_avalanche(
    result: AvalancheResult,
    *,
    view: str,
    metric: str | None,
    style: str,
    show: bool,
    save_to: str | Path | None,
) -> FigureArtifact:
    artifact = _avalanche_figure(result, view=view, metric=metric, style=style)
    _finish_figure(artifact.figure, show=show, save_to=save_to)
    return artifact


def _plot_continuous_diffusion(result, *, view, style, show, save_to):
    if view not in {"summary", "heatmap", "3d"}:
        raise ValueError("view must be summary, heatmap, or 3d")
    if style not in {"planes", "dots"}:
        raise ValueError("style must be planes or dots")
    if view != "summary" and not result.vectors:
        raise ValueError("per-output CAF vectors are not available for this result")
    pyplot = _matplotlib()
    figure = pyplot.figure(figsize=(10, 5) if view == "3d" else (9, 4), layout="constrained")
    title = f"{result.primitive_family} — {result.input_name}; λ={result.lambda_value:g}; n={len(result.samples[0])}"
    if view == "summary":
        axis = figure.add_subplot()
        axis.plot(result.round_numbers, result.factors, marker="o", markersize=4, label="CAF")
        axis.axhline(1, color="#555555", linestyle="--", label="random-sign reference (1)")
        from matplotlib.ticker import MaxNLocator

        axis.xaxis.set_major_locator(MaxNLocator(integer=True))
        axis.set(xlabel="Rounds", ylabel="Continuous avalanche factor", ylim=(0, 2), title=title)
        axis.grid(alpha=0.2)
        axis.legend()
        series: tuple[tuple[str, tuple[float, ...]], ...] = (("CAF", result.factors),)
    else:
        colors = _avalanche_colors("probability")
        if view == "heatmap":
            if len({len(row) for row in result.vectors}) != 1:
                raise ValueError("round heatmaps require equal output widths")
            axis = figure.add_subplot()
            image = axis.imshow(
                result.vectors,
                origin="lower",
                aspect="auto",
                cmap=colors,
                vmin=0,
                vmax=2,
                extent=(-0.5, len(result.vectors[0]) - 0.5, 0.5, len(result.vectors) + 0.5),
            )
            axis.set_yticks(
                range(1, len(result.round_numbers) + 1),
                labels=[str(n) for n in result.round_numbers],
            )
            axis.set(xlabel="Output bit (MSB first)", ylabel="Rounds", title=title)
            figure.colorbar(image, ax=axis, label="Mean signed-distance contribution")
        else:
            _round_profile_axis(
                figure,
                result.round_numbers,
                result.vectors,
                colors,
                style=style,
                title=title,
                label="Mean CAF contribution",
                maximum=2,
            )
        series = tuple(
            (f"round_{number}", vector)
            for number, vector in zip(result.round_numbers, result.vectors, strict=True)
        )
    artifact = FigureArtifact(
        figure,
        "continuous_diffusion" if view == "summary" else f"continuous_diffusion_{view}",
        series,
        DriverIdentity("matplotlib", DriverKind.RENDERER),
    )
    _finish_figure(figure, show=show, save_to=save_to)
    return artifact


def _round_profile_axis(figure, numbers, profiles, colors, *, style, title, label, maximum):
    from math import cos, radians, sin

    from matplotlib.cm import ScalarMappable
    from matplotlib.colors import Normalize
    from mpl_toolkits.mplot3d import Axes3D
    from mpl_toolkits.mplot3d.art3d import Poly3DCollection

    class _RoundAxes(Axes3D):
        def draw(self, renderer):
            # Parallel y-planes have an exact back-to-front order. The
            # default collection depth heuristic can hide shorter, nearer
            # rounds behind taller, farther ones. Reorder before every
            # draw so this also stays correct during interactive rotation.
            far_first = sorted(
                getattr(self, "_round_artists", ()),
                key=lambda entry: entry[0],
                reverse=sin(radians(self.azim)) * cos(radians(self.elev)) < 0,
            )
            for index, (_, base, points) in enumerate(far_first):
                base.set_zorder(2 * index + 2)
                points.set_zorder(2 * index + 3)
            super().draw(renderer)

    axis = figure.add_subplot(axes_class=_RoundAxes, computed_zorder=False)
    axis._round_artists = []
    for number, profile in zip(numbers, profiles, strict=True):
        if style == "planes":
            faces, face_colors = [], []
            for bit, value in enumerate(profile):
                faces.append(
                    [
                        (bit - 0.5, number, 0),
                        (bit - 0.5, number, value),
                        (bit + 0.5, number, value),
                        (bit + 0.5, number, 0),
                    ]
                )
                face_colors.append(colors(value / maximum))
            base = Poly3DCollection(
                faces, facecolors=face_colors, edgecolors="none", alpha=1, antialiaseds=False
            )
            axis.add_collection3d(base)
        else:
            (base,) = axis.plot(
                [-0.5, len(profile) - 0.5],
                [number, number],
                [0, 0],
                color="#bcc3c9",
                linewidth=0.65,
            )
        points = axis.scatter(
            range(len(profile)),
            [number] * len(profile),
            profile,
            c=profile,
            cmap=colors,
            vmin=0,
            vmax=maximum,
            s=3,
            depthshade=False,
        )
        axis._round_artists.append((number, base, points))
    axis.set(
        xlabel="Output bit (MSB first)",
        ylabel="Rounds",
        zlabel=label,
        zlim=(0, maximum),
        xlim=(-0.5, max(map(len, profiles)) - 0.5),
        ylim=(min(numbers) - 0.5, max(numbers) + 0.5),
        title=title,
    )
    ticks = numbers[:: max(1, (len(numbers) + 7) // 8)]
    if ticks[-1] != numbers[-1]:
        ticks += (numbers[-1],)
    axis.set_yticks(ticks)
    figure.colorbar(
        ScalarMappable(norm=Normalize(0, maximum), cmap=colors),
        ax=axis,
        label=label,
        shrink=0.7,
        pad=0.12,
    )
    return axis


def _avalanche_colors(metric):
    from matplotlib.colors import LinearSegmentedColormap

    pyplot = _matplotlib()
    base = pyplot.get_cmap("RdYlGn")
    if metric in {"entropy", "dependence"}:
        return base
    return LinearSegmentedColormap.from_list(
        "AvalancheProbability",
        [base(1 - abs(2 * index / 256 - 1)) for index in range(257)],
        N=257,
    )


def _avalanche_figure(result, *, view, metric, style):
    from claasp.analysis.avalanche import (
        _report_bounds,
        _round_data,
        _round_profiles,
        _round_statistics,
        _validate_metric,
    )

    if view not in {"summary", "heatmap", "3d"}:
        raise ValueError("view must be summary, heatmap, or 3d")
    if style not in {"planes", "dots"}:
        raise ValueError("style must be planes or dots")
    selected = _validate_metric(result.metric if metric is None else metric)
    pyplot = _matplotlib()
    round_data = _round_data(result)
    numbers = tuple(number if number is not None else 1 for number, _ in round_data)
    profiles = _round_profiles(result, selected)
    colors = _avalanche_colors(selected)
    figure = pyplot.figure(figsize=(10, 5), layout="constrained")
    title = (
        f"{result.primitive_family} — {result.input_name}; avalanche {selected}\n"
        f"n={result.sample_count}; seed={result.seed}; empirical"
    )
    if view == "summary":
        from matplotlib.ticker import MaxNLocator

        axis = figure.add_subplot()
        statistics = _round_statistics(result, selected)
        series = tuple(
            (label, tuple(getattr(item, attribute) for item in statistics))
            for label, attribute in (
                ("minimum", "minimum"),
                ("maximum", "maximum"),
                ("average", "average"),
            )
        )
        for (label, values), color in zip(series, ("#c43c39", "#7651a8", "#1764ab"), strict=True):
            axis.plot(numbers, values, marker="o", markersize=3, label=label, color=color)
        lower, upper = _report_bounds(result, selected)
        band_label = (
            "fixed tolerance band"
            if result.threshold is not None
            else "observed dependence target"
            if selected == "dependence"
            else f"{result.confidence:.0%} simultaneous SAC band"
        )
        if result.threshold is None and selected != "dependence" and (lower, upper) == (0.0, 1.0):
            band_label += " (inconclusive)"
        axis.axhspan(lower, upper, color="#d9efce", alpha=1, label=band_label)
        axis.axhline(
            lower, color="#555555", linestyle="--", linewidth=1, label=f"lower threshold {lower:g}"
        )
        axis.axhline(
            upper, color="#888888", linestyle=":", linewidth=1, label=f"upper threshold {upper:g}"
        )
        series += (
            ("lower_threshold", (lower,) * len(numbers)),
            ("upper_threshold", (upper,) * len(numbers)),
        )
        axis.set(xlabel="Rounds", ylabel=f"Avalanche {selected}", ylim=(-0.02, 1.02), title=title)
        axis.xaxis.set_major_locator(MaxNLocator(integer=True))
        axis.set_xlim(min(numbers) - 0.5, max(numbers) + 0.5)
        axis.legend(loc="best")
        axis.grid(alpha=0.2)
    elif view == "heatmap":
        if len({len(profile) for profile in profiles}) != 1:
            raise ValueError("round heatmaps require equal output widths across rounds")
        axis = figure.add_subplot()
        image = axis.imshow(
            profiles,
            origin="lower",
            aspect="auto",
            cmap=colors,
            vmin=0,
            vmax=1,
            extent=(-0.5, len(profiles[0]) - 0.5, 0.5, len(profiles) + 0.5),
        )
        axis.set_yticks(range(1, len(numbers) + 1), labels=[str(number) for number in numbers])
        axis.set(xlabel="Output bit (MSB first)", ylabel="Rounds", title=title)
        figure.colorbar(image, ax=axis, label=f"Mean avalanche {selected}")
        series = tuple(
            (f"round_{number}", profile) for number, profile in zip(numbers, profiles, strict=True)
        )
    else:
        axis = _round_profile_axis(
            figure,
            numbers,
            profiles,
            colors,
            style=style,
            title=title,
            label=f"Mean avalanche {selected}",
            maximum=1,
        )
        series = tuple(
            (f"round_{number}", profile) for number, profile in zip(numbers, profiles, strict=True)
        )
    if round_data[0][0] is None:
        if view == "summary":
            axis.set_xticks([1], labels=["unknown (final output)"])
        elif view == "heatmap":
            axis.set_yticks([1], labels=["unknown (final output)"])
        else:
            axis.set_yticks([1], labels=["unknown"])
    return FigureArtifact(
        figure, f"avalanche_{view}", series, MatplotlibPresentationDriver.identity
    )


def _plot_component_ddt(result, *, include_zero, scale, show, save_to):
    if scale not in {"counts", "probability"}:
        raise ValueError("DDT scale must be counts or probability")
    pyplot = _matplotlib()
    start = 0 if include_zero else 1
    denominator = 1 if scale == "counts" else 1 << result.input_bit_size
    values = tuple(tuple(value / denominator for value in row) for row in result.counts[start:])
    figure, axis = pyplot.subplots(figsize=(7, 4), layout="constrained")
    image = axis.imshow(
        values,
        origin="lower",
        aspect="auto",
        interpolation="nearest",
        extent=(
            -0.5,
            (1 << result.output_bit_size) - 0.5,
            start - 0.5,
            (1 << result.input_bit_size) - 0.5,
        ),
        vmin=0,
        vmax=max(max(row) for row in values),
        cmap="YlOrRd",
    )
    axis.set(
        xlabel="Output XOR difference (decimal)",
        ylabel="Input XOR difference (decimal)",
        title=f"{result.provenance.primitive or result.component_name} — S-box: exact differential {'counts' if scale == 'counts' else 'probabilities'}",
    )
    from matplotlib.ticker import MaxNLocator

    if result.output_bit_size <= 4:
        axis.set_xticks(range(1 << result.output_bit_size))
    else:
        axis.xaxis.set_major_locator(MaxNLocator(nbins=16, integer=True))
    if result.input_bit_size <= 4:
        axis.set_yticks(range(start, 1 << result.input_bit_size))
    else:
        axis.yaxis.set_major_locator(MaxNLocator(nbins=16, integer=True))
    label = (
        f"Count out of {1 << result.input_bit_size} inputs" if scale == "counts" else "Probability"
    )
    colorbar = figure.colorbar(image, ax=axis, label=label)
    if scale == "counts":
        colorbar.locator = MaxNLocator(integer=True)
        colorbar.update_ticks()
    _finish_figure(figure, show=show, save_to=save_to)
    return FigureArtifact(
        figure,
        "component_ddt",
        tuple((f"input_{index}", row) for index, row in enumerate(values, start)),
        MatplotlibPresentationDriver.identity,
    )
