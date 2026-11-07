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
    from claasp.analysis.circle_linear_trails import (
        CircleLinearTrail,
        CircleLinearTrailSearchResult,
    )

    trail = result.representative if isinstance(result, CircleLinearTrailSearchResult) else result
    if isinstance(trail, CircleLinearTrail):
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
    from claasp.analysis.circle_linear_trails import (
        CircleLinearTrail,
        CircleLinearTrailSearchResult,
    )

    searched = isinstance(result, CircleLinearTrailSearchResult)
    trail = result.representative if searched else result
    if isinstance(trail, CircleLinearTrail):
        rows = [
            ("Input mask", hex(trail.input_mask)),
            ("Output mask", hex(trail.output_mask)),
            ("Trail weight (bits)", str(trail.cost)),
            (
                "|Trail contribution| on key class",
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
                    ("Search backend", result.backend),
                    ("Search scope", result.scope),
                    ("Complete within scope", str(result.complete)),
                    (
                        "Optimal masks",
                        str(result.optimal_mask_count)
                        if result.optimal_mask_count is not None
                        else "not enumerated",
                    ),
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
    from claasp.presentation._trail import round_table

    if isinstance(trail, CircleLinearTrail) and trail.round_transitions:
        masks = (trail.input_mask, *(r.output_mask for r in trail.round_transitions))
        magnitudes = (Fraction(1), *(r.magnitude for r in trail.round_transitions))
        numbers = ("input", *(r.round_number + 1 for r in trail.round_transitions))
    elif not isinstance(trail, CircleLinearTrail):
        masks = trail.masks
        magnitudes = (Fraction(1), *(abs(c) for c in trail.coefficients))
        numbers = ("input", *range(1, len(masks)))
    else:
        masks = (trail.input_mask, trail.output_mask)
        magnitudes = (Fraction(1), Fraction(1, 1 << trail.cost))
        numbers = ("input", "output")
    cumulative_magnitude = Fraction(1)
    round_rows = []
    for number, mask, magnitude in zip(numbers, masks, magnitudes):
        cumulative_magnitude *= magnitude
        width = (trail.state_width + 3) // 4 if isinstance(trail, CircleLinearTrail) else 0
        round_rows.append(
            TableRow.of(
                number,
                f"0x{mask:0{width}x}",
                f"{magnitude.numerator}/{magnitude.denominator}",
                f"{cumulative_magnitude.numerator}/{cumulative_magnitude.denominator}",
            )
        )
    notes = [
        f"Total weight: {trail.cost if isinstance(trail, CircleLinearTrail) else trail.weight:g}."
    ]
    if searched:
        notes.insert(
            0, f"Optimal within {result.scope}." if result.complete else "Optimality not proved."
        )
    else:
        notes.insert(0, "Supplied trail; no optimality claim.")
    tables = [
        round_table(
            round_rows,
            pattern="Mask",
            quantity="|correlation|",
            notes=notes,
        )
    ]
    if isinstance(trail, CircleLinearTrail):
        key_class = (
            f"2^{trail.conditions.width - trail.conditions.rank}"
            if trail.conditions.consistent
            else "0"
        )
        scope_note = f"Absolute correlations and trail contributions apply on the satisfying key class ({key_class} keys). Signs depend on the key."
    else:
        scope_note = f"Signed trail contribution: {trail.coefficient}."
    if details:
        tables.append(_summary(rows))
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
            scope_note,
            "A selected trail contributes to a signed hull sum; its absolute contribution is not an endpoint-correlation lower bound.",
        ),
    )
