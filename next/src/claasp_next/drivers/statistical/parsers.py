"""Strict text parsers for external statistical suite artifacts."""

from __future__ import annotations

from collections.abc import Iterable

from claasp_next.analysis.statistical_results import (
    DieharderObservation,
    DieharderReport,
    NISTFinalReport,
    NISTSummaryRow,
    StatisticalAssessment,
)


def _lines(text: str | Iterable[str]) -> Iterable[str]:
    if isinstance(text, str):
        return text.splitlines()
    return text


def parse_dieharder_report(text: str | Iterable[str]) -> DieharderReport:
    """Parse Dieharder output without fabricating results for empty output.

    EXAMPLES::

        >>> try:
        ...     parse_dieharder_report()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    observations = []
    labels = {
        "PASSED": StatisticalAssessment.PASSED,
        "WEAK": StatisticalAssessment.WEAK,
        "FAILED": StatisticalAssessment.FAILED,
    }
    for line in _lines(text):
        if "|" not in line or line.lstrip().startswith("#"):
            continue
        parts = tuple(part.strip() for part in line.split("|"))
        if len(parts) != 6 or parts[-1] not in labels:
            continue
        try:
            ntuple, test_samples, pvalue_samples = map(int, parts[1:4])
            p_value = float(parts[4])
        except ValueError as error:
            raise ValueError(f"malformed Dieharder result row: {line.strip()!r}") from error
        observations.append(
            DieharderObservation(
                len(observations) + 1,
                "".join(parts[0].split()),
                ntuple,
                test_samples,
                pvalue_samples,
                p_value,
                labels[parts[-1]],
            )
        )
    if not observations:
        raise ValueError("Dieharder output contains no result rows")
    return DieharderReport(tuple(observations))


def _normalize_nist_name(name: str) -> str:
    normalized = "".join(character for character in name.lower() if character.isalnum())
    if normalized in {"dft", "fft", "fouriertransform"}:
        return "fft"
    for family in (
        "cumulativesums",
        "nonoverlappingtemplate",
        "overlappingtemplate",
        "randomexcursionsvariant",
        "randomexcursions",
        "serial",
    ):
        if normalized.startswith(family):
            return family
    return normalized


def parse_nist_final_report(text: str | Iterable[str]) -> NISTFinalReport:
    """Parse NIST STS summary rows while retaining repeated subtests.

    EXAMPLES::

        >>> try:
        ...     parse_nist_final_report()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    rows = []
    for line in _lines(text):
        parts = line.split()
        if len(parts) < 12:
            continue
        try:
            bins = tuple(int(value) for value in parts[:10])
        except ValueError:
            continue
        remaining = [value for value in parts[10:] if value != "*"]
        if len(remaining) < 3:
            continue
        uniformity_token, proportion_token = remaining[:2]
        test_name = " ".join(remaining[2:])
        try:
            uniformity = None if uniformity_token == "----" else float(uniformity_token)
            if proportion_token == "------":
                passed, total = 0, 0
            else:
                passed_token, total_token = proportion_token.split("/", 1)
                passed, total = int(passed_token), int(total_token)
        except (ValueError, TypeError) as error:
            raise ValueError(f"malformed NIST STS result row: {line.strip()!r}") from error
        rows.append(
            NISTSummaryRow(
                test_name,
                _normalize_nist_name(test_name),
                bins,
                uniformity,
                passed,
                total,
            )
        )
    if not rows:
        raise ValueError("NIST STS final report contains no result rows")
    return NISTFinalReport(tuple(rows))
