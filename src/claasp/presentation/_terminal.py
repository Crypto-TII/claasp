"""Text-stream output shared by result convenience methods."""

import sys
from typing import TextIO

from claasp.presentation.exports import render_section
from claasp.presentation.model import ReportSection


def to_terminal(section: ReportSection, *, file: TextIO | None = None) -> None:
    """Render one already-produced section to the selected terminal stream."""
    destination = sys.stdout if file is None else file
    destination.write(render_section(section, format="terminal"))
