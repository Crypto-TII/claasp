"""Explicit composition of already-produced typed results."""

from __future__ import annotations

from claasp_next.presentation.adapters import adapt_result
from claasp_next.presentation.contracts import MathematicalProvenance, PresentationProvenance
from claasp_next.presentation.model import ReportData, ReportSection


def compose_report(
    title: str,
    sections: tuple[ReportSection, ...] | list[ReportSection],
    provenance: PresentationProvenance,
) -> ReportData:
    """Compose immutable sections without executing an analysis or renderer."""

    return ReportData(title, tuple(sections), provenance)


def present(
    result: object,
    *,
    title: str | None = None,
    provenance: PresentationProvenance | None = None,
) -> ReportData:
    """Adapt one already-produced typed result into immutable report data.

    Unsupported result kinds raise a precise error containing the typed
    diagnostic returned by :func:`~claasp_next.presentation.adapt_result`.

    EXAMPLES::

        >>> from claasp_next.analysis.avalanche import AvalancheResult
        >>> result = AvalancheResult("demo", "input", 2, 7, ((0.0, 1.0),))
        >>> report = present(result)
        >>> report.sections[0].title
        'Avalanche'
    """

    adapted = adapt_result(result)
    if adapted.diagnostic is not None:
        raise TypeError(f"{adapted.diagnostic.code.value}: {adapted.diagnostic.message}")
    assert adapted.section is not None
    if provenance is None:
        method = getattr(result, "method", None) or getattr(result, "provenance", None)
        if not isinstance(method, str) or not method:
            method = f"typed {type(result).__name__} result"
        provenance = PresentationProvenance(MathematicalProvenance(method))
    return ReportData(title or adapted.section.title, (adapted.section,), provenance)
