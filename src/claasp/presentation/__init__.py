"""Dependency-free contracts and adapters for result presentation."""

from claasp._catalogue_metadata import _entry
from claasp.presentation.adapters import (
    AdaptationResult,
    adapt_result,
    avalanche_section,
    catalogue_section,
    component_property_section,
    continuous_section,
    dieharder_section,
    neural_section,
    nist_section,
    trace_section,
    trail_section,
)
from claasp.presentation.composition import compose_report, present
from claasp.presentation.contracts import (
    Applicability,
    Citation,
    DiagnosticCode,
    EvidenceClass,
    ExecutionProvenance,
    MathematicalProvenance,
    PresentationDiagnostic,
    PresentationEvidence,
    PresentationProvenance,
    PrimitiveProvenance,
    ReproducibilityMetadata,
)
from claasp.presentation.dataframe import to_dataframe
from claasp.presentation.exports import (
    cell_data,
    render_csv_table,
    render_markdown_table,
    render_section,
    render_terminal_table,
    report_data,
    section_data,
    table_data,
)
from claasp.presentation.files import Report, WrittenReport, render_report, write_report
from claasp.presentation.formatting import FormatSpec, ValueKind, format_value
from claasp.presentation.model import (
    Alignment,
    ReportData,
    ReportSection,
    Table,
    TableCell,
    TableColumn,
    TableRow,
)

__all__ = [
    "AdaptationResult",
    "Alignment",
    "Applicability",
    "Citation",
    "DiagnosticCode",
    "EvidenceClass",
    "ExecutionProvenance",
    "FormatSpec",
    "MathematicalProvenance",
    "PresentationDiagnostic",
    "PresentationEvidence",
    "PresentationProvenance",
    "PrimitiveProvenance",
    "Report",
    "ReportData",
    "ReportSection",
    "ReproducibilityMetadata",
    "Table",
    "TableCell",
    "TableColumn",
    "TableRow",
    "ValueKind",
    "WrittenReport",
    "adapt_result",
    "avalanche_section",
    "catalogue_section",
    "cell_data",
    "component_property_section",
    "compose_report",
    "continuous_section",
    "dieharder_section",
    "format_value",
    "neural_section",
    "nist_section",
    "present",
    "render_csv_table",
    "render_markdown_table",
    "render_report",
    "render_section",
    "render_terminal_table",
    "report_data",
    "section_data",
    "table_data",
    "to_dataframe",
    "trace_section",
    "trail_section",
    "write_report",
]


__catalogue__ = (
    _entry(
        "driver", render_report, name="text_presentation", kind="renderer", availability="builtin"
    ),
    _entry(
        "representation",
        ReportData,
        name="report_presentation",
        kind="presentation",
        components=(),
        domains=(),
        drivers=("matplotlib_presentation", "text_presentation"),
        scope="result",
    ),
    _entry(
        "analysis",
        present,
        name="present",
        kind="result_presentation",
        evidence="qualified",
        representations=("report_presentation",),
        drivers=("matplotlib_presentation", "text_presentation"),
        required_components=(),
        primitives=(),
        restriction="consumes already-produced typed results and never executes an analysis",
    ),
)
