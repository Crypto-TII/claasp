"""Optional Matplotlib rendering for immutable typed presentation inputs.

Matplotlib is imported only inside rendering methods. Importing this module or
the core :mod:`claasp_next.presentation` package remains dependency-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import pi

from claasp_next.analysis.avalanche import AvalancheResult
from claasp_next.analysis.component_properties import (
    PropertyClaim,
    PropertyDomain,
)
from claasp_next.analysis.statistical_results import (
    StatisticalTestRun,
)
from claasp_next.presentation.contracts import EvidenceClass
from claasp_next.provenance import DriverIdentity, DriverKind


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
        raise ImportError("Matplotlib rendering requires the optional 'plot' dependency") from error
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
        image = axis.imshow(result.probabilities, vmin=0.0, vmax=1.0, aspect="auto", cmap="viridis")
        axis.set_xlabel("output bit (MSB first)")
        axis.set_ylabel("input bit (MSB first)")
        axis.set_title(
            f"{result.primitive_family} avalanche; n={result.sample_count}; seed={result.seed}; empirical"
        )
        figure.colorbar(image, ax=axis, label="observed flip probability")
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
