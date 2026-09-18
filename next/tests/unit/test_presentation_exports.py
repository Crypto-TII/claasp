import csv
from io import StringIO
import json

import pytest

from claasp_next.presentation import (
    Alignment, Citation, DiagnosticCode, EvidenceClass, FormatSpec,
    MathematicalProvenance, PresentationDiagnostic, PresentationEvidence,
    PresentationProvenance, ReportData, ReportSection, Table, TableCell,
    TableColumn, TableRow, ValueKind, render_csv_table, render_markdown_table,
    render_section, render_terminal_table, report_data,
)


def fixed_table():
    diagnostic = PresentationDiagnostic(
        DiagnosticCode.MISSING_EVIDENCE, "first line\nsecond | line"
    )
    return Table(
        (
            TableColumn("name", "Name | property"),
            TableColumn("value", "Value", Alignment.RIGHT),
            TableColumn("note", "Note", Alignment.CENTER),
        ),
        (
            TableRow((
                TableCell("rank"), TableCell(8, FormatSpec(ValueKind.INTEGER)),
                TableCell("a,b"),
            )),
            TableRow((
                TableCell("branch"),
                TableCell(5, FormatSpec(ValueKind.INTEGER), PresentationEvidence(
                    EvidenceClass.PROVED_BOUND, complete=False, bound_direction="upper"
                )),
                TableCell(diagnostic=diagnostic),
            )),
        ),
        "Fixed table",
    )


def test_markdown_escapes_pipes_and_flattens_multiline_diagnostics():
    rendered = render_markdown_table(fixed_table())
    assert rendered.splitlines()[0] == "| Name \\| property | Value | Note |"
    assert "missing_evidence: first line<br>second \\| line" in rendered
    assert rendered.splitlines()[1] == "| :--- | ---: | :---: |"


def test_terminal_alignment_and_multiline_rows_are_deterministic():
    rendered = render_terminal_table(fixed_table())
    lines = rendered.splitlines()
    assert lines[0].rstrip().endswith("|             Note")
    assert any("first line" in line for line in lines)
    assert any("second | line" in line for line in lines)
    assert rendered == render_terminal_table(fixed_table())


def test_csv_round_trips_with_standard_library_parser():
    rendered = render_csv_table(fixed_table())
    rows = list(csv.reader(StringIO(rendered)))
    assert rows[0] == ["Name | property", "Value", "Note"]
    assert rows[1] == ["rank", "8", "a,b"]
    assert rows[2][1] == "≤5"
    assert rows[2][2] == "missing_evidence: first line\nsecond | line"
    assert rendered.endswith("\n")


def test_json_compatible_report_data_is_structural_and_preserves_evidence():
    report = ReportData(
        "Evidence",
        (ReportSection("Properties", tables=(fixed_table(),), citations=(
            Citation("fips197", "Advanced Encryption Standard", "section 5"),
        )),),
        PresentationProvenance(MathematicalProvenance(
            "fixed component evidence", ("FIPS-197",), ("aes-mixcolumns",)
        )),
    )
    data = report_data(report)
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=False)
    assert json.loads(encoded) == data
    bounded = data["sections"][0]["tables"][0]["rows"][1][1]
    assert bounded["display"] == "≤5"
    assert bounded["evidence"]["classification"] == "proved_bound"
    assert data["sections"][0]["citations"][0]["identifier"] == "fips197"


def test_section_renderer_is_explicit_about_supported_formats():
    section = ReportSection("Demo", tables=(fixed_table(),))
    assert render_section(section, format="markdown").startswith("## Demo\n")
    assert render_section(section, format="terminal").startswith("Demo\n")
    assert render_section(section, format="csv").startswith("Name | property,Value,Note")
    with pytest.raises(ValueError, match="terminal.*markdown.*csv"):
        render_section(section, format="json")
