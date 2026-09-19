"""Immutable dependency-free table and report-data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from claasp_next.presentation.contracts import (
    Citation,
    PresentationDiagnostic,
    PresentationEvidence,
    PresentationProvenance,
)
from claasp_next.presentation.formatting import FormatSpec, format_value


class Alignment(str, Enum):
    """Portable alignment for table columns.

    EXAMPLES::

        >>> tuple(member.value for member in Alignment)
        ('left', 'right', 'center')
    """

    LEFT = "left"
    RIGHT = "right"
    CENTER = "center"


@dataclass(frozen=True, slots=True)
class TableColumn:
    """Stable column key, human heading, and alignment.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (TableColumn.__dataclass_params__.frozen, tuple(field.name for field in fields(TableColumn)))
        (True, ('key', 'heading', 'alignment'))
    """

    key: str
    heading: str
    alignment: Alignment = Alignment.LEFT

    def __post_init__(self) -> None:
        if not self.key or not self.heading:
            raise ValueError("column key and heading must not be empty")
        if not isinstance(self.alignment, Alignment):
            object.__setattr__(self, "alignment", Alignment(self.alignment))


@dataclass(frozen=True, slots=True)
class TableCell:
    """A typed display value with optional evidence or diagnostic.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (TableCell.__dataclass_params__.frozen, tuple(field.name for field in fields(TableCell)))
        (True, ('value', 'format', 'evidence', 'diagnostic'))
    """

    value: object | None = None
    format: FormatSpec = field(default_factory=FormatSpec)
    evidence: PresentationEvidence | None = None
    diagnostic: PresentationDiagnostic | None = None

    def __post_init__(self) -> None:
        if self.diagnostic is not None and self.value is not None:
            raise ValueError("diagnostic cells cannot also contain a value")
        if self.evidence is not None and self.evidence.diagnostic is not None:
            if self.diagnostic is not None and self.diagnostic != self.evidence.diagnostic:
                raise ValueError("cell and evidence diagnostics disagree")

    @property
    def text(self) -> str:
        """Return deterministic plain text for this cell."""

        diagnostic = self.diagnostic or (self.evidence.diagnostic if self.evidence else None)
        if diagnostic is not None:
            return f"{diagnostic.code.value}: {diagnostic.message}"
        rendered = format_value(self.value, self.format)
        if self.evidence is not None and self.evidence.bound_direction is not None:
            return ("≥" if self.evidence.bound_direction == "lower" else "≤") + rendered
        return rendered


@dataclass(frozen=True, slots=True)
class TableRow:
    """One immutable row in declared column order.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (TableRow.__dataclass_params__.frozen, tuple(field.name for field in fields(TableRow)))
        (True, ('cells',))
    """

    cells: tuple[TableCell, ...]

    @classmethod
    def of(cls, *values: object) -> TableRow:
        """Construct a text-oriented row, preserving caller order."""

        return cls(
            tuple(
                value if isinstance(value, TableCell) else TableCell(str(value)) for value in values
            )
        )


@dataclass(frozen=True, slots=True)
class Table:
    """A generic ordered table independent of pandas and renderers.

    EXAMPLES::

        >>> table = Table(
        ...     (TableColumn("name", "Name"), TableColumn("value", "Value", Alignment.RIGHT)),
        ...     (TableRow.of("weight", "4"),),
        ... )
        >>> table.rows[0].cells[0].text
        'weight'
    """

    columns: tuple[TableColumn, ...]
    rows: tuple[TableRow, ...]
    title: str | None = None
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.columns:
            raise ValueError("tables require at least one column")
        if len({column.key for column in self.columns}) != len(self.columns):
            raise ValueError("table column keys must be unique")
        if any(len(row.cells) != len(self.columns) for row in self.rows):
            raise ValueError("every row must have exactly one cell per column")
        if any(not note for note in self.notes):
            raise ValueError("table notes must not be empty")


@dataclass(frozen=True, slots=True)
class ReportSection:
    """A titled report section containing prose and ordered tables.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (ReportSection.__dataclass_params__.frozen, tuple(field.name for field in fields(ReportSection)))
        (True, ('title', 'paragraphs', 'tables', 'citations'))
    """

    title: str
    paragraphs: tuple[str, ...] = ()
    tables: tuple[Table, ...] = ()
    citations: tuple[Citation, ...] = ()

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("section title must not be empty")
        if not self.paragraphs and not self.tables:
            raise ValueError("a report section must contain prose or a table")


@dataclass(frozen=True, slots=True)
class ReportData:
    """Immutable presentation data; serialization is deliberately external.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (ReportData.__dataclass_params__.frozen, tuple(field.name for field in fields(ReportData)))
        (True, ('title', 'sections', 'provenance'))
    """

    title: str
    sections: tuple[ReportSection, ...]
    provenance: PresentationProvenance

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("report title must not be empty")
        if not self.sections:
            raise ValueError("report data requires at least one section")
        if not isinstance(self.provenance, PresentationProvenance):
            raise TypeError("report provenance has the wrong type")
