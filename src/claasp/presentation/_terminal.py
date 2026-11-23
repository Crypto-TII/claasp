"""Text-stream output shared by result convenience methods."""

import sys
from typing import TextIO

from claasp.presentation.exports import render_section
from claasp.presentation.model import ReportSection


def to_terminal(section: ReportSection, *, file: TextIO | None = None) -> None:
    """Render one already-produced section to the selected terminal stream."""
    destination = sys.stdout if file is None else file
    destination.write(render_section(section, format="terminal"))


def _trail_to_terminal(result, *, details=False, value_format="hex", file=None):
    """Keep named input evidence in reports, but omit its redundant terminal table."""
    from dataclasses import replace

    from claasp.presentation.adapters import trail_section

    section = trail_section(result, details=details, value_format=value_format)
    section = replace(
        section,
        tables=tuple(table for table in section.tables if table.title != "External input patterns"),
    )
    to_terminal(section, file=file)
