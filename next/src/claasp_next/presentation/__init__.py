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

__all__ = [
    "Applicability", "Citation", "DiagnosticCode", "EvidenceClass",
    "ExecutionProvenance", "MathematicalProvenance", "PresentationDiagnostic",
    "PresentationEvidence", "PresentationProvenance", "PrimitiveProvenance",
    "ReproducibilityMetadata",
    "Alignment", "FormatSpec", "ReportData", "ReportSection", "Table", "TableCell",
    "TableColumn", "TableRow", "ValueKind", "format_value",
]
