"""Read-only presentation of circle-linear correlations and trail contributions."""

from fractions import Fraction
from math import log2

from claasp.presentation.model import ReportSection, Table, TableColumn, TableRow


def _summary(rows):
    return Table(
        (TableColumn("quantity", "Quantity"), TableColumn("value", "Value")),
        tuple(TableRow.of(name, value) for name, value in rows),
    )


def correlation_section(result):
    from claasp.analysis.circle_linear import CircleApproximation

    if isinstance(result, CircleApproximation):
        rows: tuple[tuple[str, str], ...] = (
            ("Input mask", hex(result.input_mask)),
            ("Output mask", hex(result.output_mask)),
            ("Signed correlation", str(result.coefficient)),
            ("Complete", str(result.complete)),
        )
        return ReportSection(
            "Circle-linear endpoint approximation",
            tables=(_summary(rows),),
            paragraphs=(
                (
                    "Actual input/output correlation; all inputs were enumerated."
                    if result.complete
                    else "Incomplete endpoint result; the coefficient does not establish endpoint probabilities."
                ),
            ),
        )
    rows = (
        ("Estimated correlation", f"{result.value:.6g}"),
        ("Confidence interval", f"[{result.lower:.6g}, {result.upper:.6g}]"),
        ("Confidence", f"{result.confidence:.1%}"),
        ("Samples", str(result.samples)),
        ("Seed", str(result.seed)),
        ("Standard error", f"{result.standard_error:.6g}"),
    )
    return ReportSection(
        "Circle-linear endpoint estimate",
        tables=(_summary(rows),),
        paragraphs=("Empirical fixed-input correlation with a Hoeffding confidence interval.",),
    )


def trail_profile(result):
    """Read retained transitions; do not repeat a search or run a primitive."""
    from claasp.analysis.circle_linear_spn import SubgroupSearchResult, SubgroupTrail

    trail = result.representative if isinstance(result, SubgroupSearchResult) else result
    if isinstance(trail, SubgroupTrail):
        if not trail.conditions.consistent:
            raise ValueError("trail has no satisfying key; no nonzero contribution to plot")
        coefficients = tuple(t.magnitude for t in reversed(trail._affine_steps))
        unit = "Round"
    else:
        coefficients = trail.coefficients
        unit = "Layer"
    if any(not c for c in coefficients):
        raise ValueError("weight profiles require nonzero local coefficients")
    relative = (0.0, *(max(0.0, -log2(abs(c))) for c in coefficients))
    cumulative = [0.0]
    for weight in relative[1:]:
        cumulative.append(cumulative[-1] + weight)
    return unit, relative, tuple(cumulative)


def trail_section(result, *, details=False):
    from claasp.analysis.circle_linear_spn import SubgroupSearchResult, SubgroupTrail

    searched = isinstance(result, SubgroupSearchResult)
    trail = result.representative if searched else result
    if isinstance(trail, SubgroupTrail):
        rows = [
            ("Input mask", hex(trail.input_mask)),
            ("Output mask", hex(trail.output_mask)),
            ("Trail weight (bits)", str(trail.cost)),
            (
                "Contribution magnitude on key class",
                str(Fraction(1, 1 << trail.cost) if trail.conditions.consistent else 0),
            ),
            (
                "Keys in class",
                f"2^{trail.conditions.width - trail.conditions.rank}"
                if trail.conditions.consistent
                else "0",
            ),
            (
                "Key constraints",
                str(trail.conditions.rank) if trail.conditions.consistent else "inconsistent",
            ),
        ]
        if searched:
            rows.extend(
                (
                    ("Search scope", result.scope),
                    ("Complete within scope", str(result.complete)),
                    ("Optimal masks", str(result.optimal_mask_count)),
                )
            )
        else:
            rows.append(("Search scope", "supplied canonical trail; no optimality claim"))
    else:
        rows = [
            ("Input mask", hex(trail.masks[0])),
            ("Output mask", hex(trail.masks[-1])),
            ("Signed trail contribution", str(trail.coefficient)),
            ("Trail weight (bits)", f"{trail.weight:g}"),
            ("Search scope", "supplied layer sequence; no optimality claim"),
        ]
    tables = [_summary(rows)]
    if details:
        unit, relative, cumulative = trail_profile(result)
        tables.append(
            Table(
                (
                    TableColumn("step", unit),
                    TableColumn("relative", "Relative weight (bits)"),
                    TableColumn("cumulative", "Cumulative weight (bits)"),
                ),
                tuple(
                    TableRow.of(i, f"{r:g}", f"{c:g}")
                    for i, (r, c) in enumerate(zip(relative, cumulative))
                ),
            )
        )
    return ReportSection(
        "Circle-linear trail contribution",
        tables=tuple(tables),
        paragraphs=(
            "A selected trail contributes to a signed hull sum; its magnitude is not an endpoint-correlation lower bound.",
        ),
    )
