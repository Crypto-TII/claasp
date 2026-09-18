"""Dependency-free contracts and adapters for result presentation."""

from claasp_next.presentation.contracts import (
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
from claasp_next.presentation.formatting import FormatSpec, ValueKind, format_value
from claasp_next.presentation.model import (
    Alignment, ReportData, ReportSection, Table, TableCell, TableColumn, TableRow,
)
from claasp_next.presentation.adapters import (
    AdaptationResult, adapt_result, avalanche_section, catalogue_section,
    component_property_section, continuous_section, dieharder_section, neural_section,
    nist_section, trace_section, trail_section,
)
from claasp_next.presentation.exports import (
    cell_data, render_csv_table, render_markdown_table, render_section,
    render_terminal_table, report_data, section_data, table_data,
)
from claasp_next.presentation.composition import compose_report, present
from claasp_next.presentation.dataframe import to_dataframe
from claasp_next.presentation.files import WrittenReport, render_report, write_report

__all__ = [
    "Applicability", "Citation", "DiagnosticCode", "EvidenceClass",
    "ExecutionProvenance", "MathematicalProvenance", "PresentationDiagnostic",
    "PresentationEvidence", "PresentationProvenance", "PrimitiveProvenance",
    "ReproducibilityMetadata",
    "Alignment", "FormatSpec", "ReportData", "ReportSection", "Table", "TableCell",
    "TableColumn", "TableRow", "ValueKind", "format_value",
    "AdaptationResult", "adapt_result", "avalanche_section", "catalogue_section",
    "component_property_section", "continuous_section", "dieharder_section",
    "neural_section", "nist_section", "trace_section", "trail_section",
    "cell_data", "render_csv_table", "render_markdown_table", "render_section",
    "render_terminal_table", "report_data", "section_data", "table_data",
    "WrittenReport", "compose_report", "present", "render_report", "to_dataframe",
    "write_report",
]
