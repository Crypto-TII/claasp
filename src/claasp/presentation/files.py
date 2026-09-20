"""Safe, explicit file output for human-facing reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from claasp.presentation.exports import render_section, report_data
from claasp.presentation.model import ReportData

_EXTENSIONS = {
    "terminal": ".txt",
    "markdown": ".md",
    "csv": ".csv",
    "json": ".json",
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
        raise ValueError("format must be one of: terminal, markdown, csv, json")
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
    if normalized not in {"terminal", "markdown"}:
        raise ValueError("human-readable report format must be terminal or markdown")
    heading = f"# {report.title}\n" if normalized == "markdown" else report.title + "\n"
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
    return heading + "\n" + sections + "\n" + label + "\n\n" + "\n".join(lines) + "\n"
