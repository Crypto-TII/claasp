"""Presentation of retained exact word-characteristic queries."""

from claasp.presentation._trail_values import _format_trail_value, _validate_value_format
from claasp.presentation.model import ReportSection, Table, TableColumn, TableRow


def _summary(rows, title):
    return Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value")),
        tuple(TableRow.of(*row) for row in rows),
        title,
    )


def _inputs(trail, linear, value_format):
    values = trail.input_masks if linear else trail.input_differences
    widths = dict(trail.input_widths)
    return ", ".join(
        f"{name}={_format_trail_value(value, widths.get(name), value_format=value_format)}"
        for name, value in values
    )


def _components(trail, title, linear, value_format):
    columns = [
        TableColumn("component", "Component"),
        TableColumn("input", "Input"),
        TableColumn("output", "Output"),
        TableColumn("weight", "Weight"),
    ]
    if linear:
        columns.append(TableColumn("sign", "Sign"))
    rows = []
    for step in trail.steps:
        transition = step.transition
        values = [
            step.component_id,
            _format_trail_value(
                transition.input_pattern.value,
                transition.input_pattern.width,
                value_format=value_format,
            ),
            _format_trail_value(
                transition.output_pattern.value,
                transition.output_pattern.width,
                value_format=value_format,
            ),
            f"{transition.weight:.6g}",
        ]
        if linear:
            values.append(str(transition.sign))
        rows.append(TableRow.of(*values))
    return Table(tuple(columns), tuple(rows), title)


def characteristic_section(trail, *, linear, details=False, value_format="hex"):
    _validate_value_format(value_format)
    output = trail.output_mask if linear else trail.output_difference
    rows = [
        ("weight", f"{trail.total_weight:.6g}"),
        ("input", _inputs(trail, linear, value_format)),
        ("output", _format_trail_value(output, trail.output_width, value_format=value_format)),
    ]
    if linear:
        rows.append(("sign", str(trail.sign)))
    tables = [_summary(rows, "Characteristic summary")]
    if details:
        tables.append(_components(trail, "Component transitions", linear, value_format))
    return ReportSection(
        "XOR-linear characteristic" if linear else "XOR-differential characteristic",
        ("Component characteristic; no optimality claim.",),
        tuple(tables),
    )


def enumeration_section(result, *, linear, details=False, value_format="hex"):
    _validate_value_format(value_format)
    metadata = dict(result.reproducibility)
    rows = [
        ("characteristics", str(len(result.trails))),
        ("complete", "yes" if result.complete else "no"),
        ("runtime (seconds)", f"{result.runtime_seconds:.6f}"),
    ]
    for key in ("primitive", "solver"):
        if key in metadata:
            rows.append((key.replace("_", " "), metadata[key]))
    columns = [
        TableColumn("index", "Index"),
        TableColumn("weight", "Weight"),
        TableColumn("input", "Input"),
        TableColumn("output", "Output"),
    ]
    if linear:
        columns.append(TableColumn("sign", "Sign"))
    trails = []
    for index, trail in enumerate(result.trails):
        output = trail.output_mask if linear else trail.output_difference
        values = [
            str(index),
            f"{trail.total_weight:.6g}",
            _inputs(trail, linear, value_format),
            _format_trail_value(output, trail.output_width, value_format=value_format),
        ]
        if linear:
            values.append(str(trail.sign))
        trails.append(TableRow.of(*values))
    tables = [
        _summary(rows, "Enumeration summary"),
        Table(tuple(columns), tuple(trails), "Characteristics"),
    ]
    if details:
        tables.extend(
            _components(trail, f"Characteristic {index} components", linear, value_format)
            for index, trail in enumerate(result.trails)
        )
    status = (
        "Complete enumeration for the requested model and weight range."
        if result.complete
        else "Incomplete enumeration: more characteristics may exist (limit or solver interruption)."
    )
    notes = (
        (status, "No characteristics satisfy the query.")
        if result.complete and not result.trails
        else (status,)
    )
    return ReportSection(
        "XOR-linear trail enumeration" if linear else "XOR-differential trail enumeration",
        notes,
        tuple(tables),
    )
