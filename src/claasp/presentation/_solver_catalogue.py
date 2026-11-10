"""Render solver queries from the shared catalogue's driver/probe records."""


def _to_terminal(result, *, file=None):
    from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

    columns = [
        TableColumn(key, title)
        for key, title in (
            ("solver", "Solver"),
            ("driver", "Driver"),
            ("dependency", "Dependency"),
        )
    ]
    checked = result.view != "supported"
    if checked:
        columns.extend(
            (TableColumn("available", "Available"), TableColumn("evidence", "Detection evidence"))
        )
    probes = {probe.driver.name: probe for probe in result.availability}
    rows = []
    for record in result.entries:
        cells = [
            record.name,
            record.implementation.rsplit(":", 1)[-1],
            record.target or "builtin",
        ]
        if checked:
            probe = probes[record.name]
            cells.extend(
                (
                    "yes" if probe.available else "no",
                    probe.detail or probe.resolved or "dependency not detected",
                )
            )
        rows.append(TableRow.of(*cells))
    print(render_terminal_table(Table(tuple(columns), tuple(rows))), file=file)
    if checked:
        print(
            "Availability uses registered dependency/configuration probes. Licenses, successful solves "
            "and per-analysis compatibility are not checked.",
            file=file,
        )
    if not result.entries:
        print("No registered solver matched this view.", file=file)
