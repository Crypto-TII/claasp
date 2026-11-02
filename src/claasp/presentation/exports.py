"""Deterministic text and JSON-compatible report-data exports."""

from __future__ import annotations

import csv
from dataclasses import fields, is_dataclass
from enum import Enum
from io import StringIO
from types import MappingProxyType

from claasp.presentation.model import Alignment, ReportData, ReportSection, Table, TableCell


def _markdown(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "<br>")
    )


def render_markdown_table(table: Table) -> str:
    """Render an escaped GitHub-flavored Markdown table.

    EXAMPLES::

        >>> try:
        ...     render_markdown_table()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    alignments = {
        Alignment.LEFT: ":---",
        Alignment.RIGHT: "---:",
        Alignment.CENTER: ":---:",
    }
    lines = [
        "| " + " | ".join(_markdown(column.heading) for column in table.columns) + " |",
        "| " + " | ".join(alignments[column.alignment] for column in table.columns) + " |",
    ]
    lines.extend(
        "| " + " | ".join(_markdown(cell.text) for cell in row.cells) + " |" for row in table.rows
    )
    return "\n".join(lines)


def render_terminal_table(table: Table) -> str:
    """Render an aligned terminal table, expanding multiline cells safely.

    EXAMPLES::

        >>> try:
        ...     render_terminal_table()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    row_lines = [
        tuple(cell.text.replace("\r\n", "\n").replace("\r", "\n").split("\n") for cell in row.cells)
        for row in table.rows
    ]
    widths = []
    for index, column in enumerate(table.columns):
        candidates = [column.heading]
        candidates.extend(line for row in row_lines for line in row[index])
        widths.append(max(len(value) for value in candidates))

    def aligned(value: str, index: int) -> str:
        alignment = table.columns[index].alignment
        if alignment is Alignment.RIGHT:
            return value.rjust(widths[index])
        if alignment is Alignment.CENTER:
            return value.center(widths[index])
        return value.ljust(widths[index])

    lines = [
        " | ".join(aligned(column.heading, index) for index, column in enumerate(table.columns))
    ]
    lines.append("-+-".join("-" * width for width in widths))
    for row in row_lines:
        height = max(len(cell_lines) for cell_lines in row)
        for line_index in range(height):
            lines.append(
                " | ".join(
                    aligned(cell_lines[line_index] if line_index < len(cell_lines) else "", index)
                    for index, cell_lines in enumerate(row)
                )
            )
    return "\n".join(lines)


def render_csv_table(table: Table) -> str:
    """Render RFC-4180-style CSV using only the standard library.

    EXAMPLES::

        >>> try:
        ...     render_csv_table()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(column.heading for column in table.columns)
    writer.writerows(tuple(cell.text for cell in row.cells) for row in table.rows)
    return output.getvalue()


def _compatible(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (tuple, list)):
        return [_compatible(item) for item in value]
    if isinstance(value, (dict, MappingProxyType)):
        return {
            str(key): _compatible(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        return sorted((_compatible(item) for item in value), key=str)
    if is_dataclass(value):
        return {field.name: _compatible(getattr(value, field.name)) for field in fields(value)}
    raise TypeError(f"{type(value).__name__} is not JSON-compatible report data")


def cell_data(cell: TableCell) -> dict[str, object]:
    """Return structured data for one cell without serializing it.

    EXAMPLES::

        >>> try:
        ...     cell_data()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    data: dict[str, object] = {
        "value": _compatible(cell.value),
        "display": cell.text,
        "format": _compatible(cell.format),
    }
    if cell.evidence is not None:
        data["evidence"] = _compatible(cell.evidence)
    if cell.diagnostic is not None:
        data["diagnostic"] = _compatible(cell.diagnostic)
    return data


def table_data(table: Table) -> dict[str, object]:
    """Return recursively JSON-compatible data for one immutable table.

    EXAMPLES::

        >>> try:
        ...     table_data()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    return {
        "title": table.title,
        "columns": [_compatible(column) for column in table.columns],
        "rows": [[cell_data(cell) for cell in row.cells] for row in table.rows],
        "notes": list(table.notes),
    }


def section_data(section: ReportSection) -> dict[str, object]:
    """Return recursively JSON-compatible data for a report section.

    EXAMPLES::

        >>> try:
        ...     section_data()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    return {
        "title": section.title,
        "paragraphs": list(section.paragraphs),
        "tables": [table_data(table) for table in section.tables],
        "citations": [_compatible(citation) for citation in section.citations],
    }


def report_data(report: ReportData) -> dict[str, object]:
    """Return JSON-compatible report data, not a versioned serialization.

    EXAMPLES::

        >>> from claasp.presentation import *
        >>> provenance = PresentationProvenance(MathematicalProvenance("fixed evidence"))
        >>> table = Table((TableColumn("v", "Value"),), (TableRow.of("ok"),))
        >>> data = report_data(ReportData("Demo", (ReportSection("Result", tables=(table,)),), provenance))
        >>> data["sections"][0]["tables"][0]["rows"][0][0]["display"]
        'ok'
    """

    return {
        "title": report.title,
        "sections": [section_data(section) for section in report.sections],
        "provenance": _compatible(report.provenance),
    }


def _latex(value: str) -> str:
    """Escape plain report text without allowing TeX commands through."""
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
        "≥": r"\ensuremath{\geq}",
        "≤": r"\ensuremath{\leq}",
    }
    return "".join(
        replacements.get(char, char) for char in value.replace("\r\n", "\n").replace("\r", "\n")
    ).replace("\n", " ")


def _render_latex_table(table: Table) -> str:
    alignments = {Alignment.LEFT: "l", Alignment.RIGHT: "r", Alignment.CENTER: "c"}
    spec = "".join(alignments[column.alignment] for column in table.columns)
    lines = [r"\begin{tabular}{" + spec + "}", r"\hline"]
    lines.append(" & ".join(_latex(column.heading) for column in table.columns) + r" \\")
    lines.append(r"\hline")
    lines.extend(" & ".join(_latex(cell.text) for cell in row.cells) + r" \\" for row in table.rows)
    lines.extend((r"\hline", r"\end{tabular}"))
    return "\n".join(lines)


def render_section(
    section: ReportSection,
    *,
    format: str = "terminal",  # noqa: A002 - public format API
) -> str:
    """Render one section as terminal, Markdown, CSV, or LaTeX text.

    EXAMPLES::

        >>> try:
        ...     render_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    normalized = format.lower()
    if normalized not in {"terminal", "markdown", "csv", "latex"}:
        raise ValueError("format must be terminal, markdown, csv, or latex")
    renderer = {
        "terminal": render_terminal_table,
        "markdown": render_markdown_table,
        "csv": render_csv_table,
        "latex": _render_latex_table,
    }[normalized]
    if normalized == "csv":
        if section.paragraphs or len(section.tables) != 1:
            raise ValueError("CSV section rendering requires exactly one table and no prose")
        return renderer(section.tables[0])
    escape = _latex if normalized == "latex" else str
    blocks = []
    if normalized == "markdown":
        blocks.append(f"## {section.title}")
    elif normalized == "latex":
        blocks.append(r"\subsection*{" + _latex(section.title) + "}")
    elif normalized == "terminal":
        blocks.append(section.title)
    blocks.extend(escape(paragraph) for paragraph in section.paragraphs)
    for table in section.tables:
        if table.title:
            blocks.append(f"### {table.title}" if normalized == "markdown" else escape(table.title))
        blocks.append(renderer(table))
        blocks.extend(escape(note) for note in table.notes)
    if section.citations:
        blocks.append("Citations")
        blocks.extend(
            escape(
                f"[{citation.identifier}] {citation.title}"
                + (f" ({citation.locator})" if citation.locator else "")
            )
            for citation in section.citations
        )
    return "\n\n".join(blocks) + "\n"
