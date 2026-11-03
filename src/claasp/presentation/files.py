"""Safe, explicit file output for human-facing reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from claasp.presentation.composition import present
from claasp.presentation.exports import _latex, render_section, report_data
from claasp.presentation.model import ReportData

_EXTENSIONS = {
    "terminal": ".txt",
    "markdown": ".md",
    "csv": ".csv",
    "json": ".json",
    "latex": ".tex",
}


@dataclass(frozen=True, slots=True)
class WrittenReport:
    """The explicit path, format, and UTF-8 byte count of one written report.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (WrittenReport.__dataclass_params__.frozen, tuple(field.name for field in fields(WrittenReport)))
        (True, ('path', 'format', 'byte_count'))
    """

    path: Path
    format: str
    byte_count: int


def _validated_path(path: str | Path, output_format: str) -> Path:
    if output_format not in _EXTENSIONS:
        raise ValueError("format must be one of: terminal, markdown, csv, json, latex")
    candidate = Path(path)
    if not candidate.name or any(part == ".." for part in candidate.parts):
        raise ValueError("output path must be explicit and must not contain '..'")
    if candidate.suffix.lower() != _EXTENSIONS[output_format]:
        raise ValueError(
            f"{output_format} output requires the {_EXTENSIONS[output_format]} extension"
        )
    if candidate.exists() and candidate.is_dir():
        raise IsADirectoryError(candidate)
    if candidate.is_symlink():
        raise ValueError("refusing to write a report through a symbolic link")
    return candidate


def write_report(
    report: ReportData,
    path: str | Path,
    *,
    format: str,  # noqa: A002 - public format API
    overwrite: bool = False,
    create_parents: bool = False,
) -> WrittenReport:
    """Write one report with an explicit format, extension, and overwrite policy.

    The function never derives directories from primitive or test names and
    never adds a timestamp. Parent creation is opt-in and applies only to the
    exact parent supplied by the caller.


    EXAMPLES::

        >>> try:
        ...     write_report()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    normalized = format.strip().lower()
    destination = _validated_path(path, normalized)
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)
    if not destination.parent.exists():
        if not create_parents:
            raise FileNotFoundError(destination.parent)
        destination.parent.mkdir(parents=True, exist_ok=False)
    if normalized == "json":
        text = json.dumps(report_data(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    elif normalized == "csv":
        if len(report.sections) != 1:
            raise ValueError("CSV report output requires exactly one section")
        text = render_section(report.sections[0], format="csv")
    else:
        text = render_report(report, format=normalized)
    mode = "w" if overwrite else "x"
    with destination.open(mode, encoding="utf-8", newline="\n") as output:
        output.write(text)
    return WrittenReport(destination, normalized, len(text.encode("utf-8")))


def render_report(
    report: ReportData,
    *,
    format: str = "terminal",  # noqa: A002 - public format API
) -> str:
    """Render a complete human-readable report with citations and provenance.

    EXAMPLES::

        >>> try:
        ...     render_report()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    normalized = format.strip().lower()
    if normalized not in {"terminal", "markdown", "latex"}:
        raise ValueError("human-readable report format must be terminal, markdown, or latex")
    heading = f"# {report.title}\n" if normalized == "markdown" else report.title + "\n"
    if normalized == "latex":
        heading = r"\section*{" + _latex(report.title) + "}\n"
    sections = "\n".join(render_section(section, format=normalized) for section in report.sections)
    mathematical = report.provenance.mathematical
    lines = [f"method: {mathematical.method}"]
    lines.extend(f"source: {source}" for source in mathematical.sources)
    lines.extend(f"fixed evidence: {item}" for item in mathematical.fixed_evidence)
    if report.provenance.primitive is not None:
        lines.append(f"primitive: {report.provenance.primitive.primitive}")
        if report.provenance.primitive.realization is not None:
            lines.append(f"realization: {report.provenance.primitive.realization}")
    if report.provenance.execution is not None:
        execution = report.provenance.execution
        version = f" {execution.driver.version}" if execution.driver.version else ""
        lines.append(f"driver: {execution.driver.name}{version}")
        if execution.command:
            lines.append("command: " + " ".join(execution.command))
        if execution.runtime_seconds is not None:
            lines.append(f"runtime seconds: {execution.runtime_seconds:.6g}")
    for citation in report.provenance.citations:
        locator = f" ({citation.locator})" if citation.locator else ""
        lines.append(f"citation [{citation.identifier}]: {citation.title}{locator}")
    label = "## Provenance" if normalized == "markdown" else "Provenance"
    if normalized == "latex":
        label = r"\subsection*{Provenance}"
        lines = [_latex(line) for line in lines]
    return heading + "\n" + sections + "\n" + label + "\n\n" + "\n".join(lines) + "\n"


class Report:
    """Present an existing analysis result or immutable report data.

    Construction never runs an analysis. Rendering and file output delegate
    to the shared presentation layer.

    EXAMPLES::

        >>> from claasp.analysis.avalanche import AvalancheResult
        >>> report = Report(AvalancheResult("demo", "input", 2, 7, ((0.0, 1.0),)))
        >>> report.data.title
        'Avalanche'
    """

    def __init__(self, result: object) -> None:
        self.data = result if isinstance(result, ReportData) else present(result)

    def render(self, *, format: str = "terminal") -> str:  # noqa: A002 - public format API
        """Return terminal, Markdown, or LaTeX text without printing it.

        EXAMPLES::

            >>> Report.render.__name__
            'render'
        """
        return render_report(self.data, format=format)

    def to_latex(self) -> str:
        """Return an escaped LaTeX fragment for inclusion in a document.

        EXAMPLES::

            >>> Report.to_latex.__name__
            'to_latex'
        """
        return self.render(format="latex")

    def to_terminal(self, *, file: TextIO | None = None) -> None:
        """Print the report to the terminal or a supplied text stream.

        EXAMPLES::

            >>> Report.to_terminal.__name__
            'to_terminal'
        """
        print(self.render(), end="", file=file)

    def save(
        self,
        path: str | Path,
        *,
        format: str,  # noqa: A002 - public format API
        overwrite: bool = False,
        create_parents: bool = False,
    ) -> WrittenReport:
        """Save a report with an explicit format and overwrite policy.

        EXAMPLES::

            >>> Report.save.__name__
            'save'
        """
        return write_report(
            self.data, path, format=format, overwrite=overwrite, create_parents=create_parents
        )
