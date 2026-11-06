"""Presentation of retained circle-differential evidence; never re-evaluate."""

from fractions import Fraction

from claasp.presentation._trail import round_table
from claasp.presentation.model import ReportSection, Table, TableColumn, TableRow


def probability_section(result):
    event = result.event.replace("_", " ")
    rows = [
        ("Input difference", hex(result.input_difference)),
        ("Output difference", hex(result.output_difference)),
        ("Probability" if result.complete else "Estimated probability", str(result.probability)),
        ("Hits / ordered pairs", f"{result.hits} / {result.trials}"),
        ("Complete input domain", str(result.complete)),
        ("Fixed inputs", repr(dict(result.fixed_inputs))),
    ]
    if not result.complete:
        rows.extend(
            [
                ("Confidence interval", f"[{result.lower:.6g}, {result.upper:.6g}]"),
                ("Confidence", f"{result.confidence:.1%}"),
                ("Seed", str(result.seed)),
                ("Standard error", f"{result.standard_error:.6g}"),
            ]
        )
    return ReportSection(
        f"Circle-differential {event} {'probability' if result.complete else 'estimate'}",
        tables=(
            Table(
                (TableColumn("quantity", "Quantity"), TableColumn("value", "Value")),
                tuple(TableRow.of(a, b) for a, b in rows),
            ),
        ),
        paragraphs=(
            "Differences use original packed elements of the declared circle operations. All other inputs are fixed; no key averaging is performed.",
        ),
    )


def trail_section(result, *, details=False):
    sampled = not result.evidence.complete
    relative = (Fraction(1), *result.conditional_probabilities)
    rows = tuple(
        TableRow.of(
            label,
            hex(difference),
            str(probability) if probability is not None else "undefined",
            str(Fraction(count, result.evidence.trials)),
        )
        for label, difference, probability, count in zip(
            result.boundary_labels, result.differences, relative, result.prefix_counts
        )
    )
    notes = ["Relative probabilities are conditioned on the entire preceding prefix."]
    if result.searched:
        notes.append(
            "Optimal for the fixed input difference, observed boundaries and any supplied endpoint constraint; complete input enumeration."
        )
    else:
        notes.append("Supplied concrete trail; no optimality claim.")
    if sampled:
        evidence = result.evidence
        notes.append(f"Samples: {evidence.trials}; Seed: {evidence.seed}.")
        notes.append(
            f"Final probability estimate: {float(evidence.probability):.6g}; "
            f"{evidence.confidence:.0%} confidence interval: "
            f"[{evidence.lower:.6g}, {evidence.upper:.6g}]."
        )
    tables = [
        round_table(
            rows,
            pattern="Difference",
            quantity="estimated conditional probability" if sampled else "conditional probability",
            cumulative_quantity="estimated probability" if sampled else "probability",
            notes=notes,
        )
    ]
    if details:
        tables.extend(probability_section(result.evidence).tables)
    return ReportSection(
        "Circle-differential concrete trail estimate"
        if sampled
        else "Circle-differential concrete trail",
        tables=tuple(tables),
        paragraphs=(
            "Probabilities count actual executions at the retained fixed inputs. These conditional factors are not standalone local DDT probabilities.",
            f"Witness input pair: {result.witness}.",
            "The endpoint differential combines all compatible concrete trails.",
        ),
    )
