"""Deterministic source representations compiled from typed graphs."""

from claasp_next.representations.source.c import C_COMPILER, compile_c_source
from claasp_next.representations.source.model import (
    SourceArtifact,
    SourceCompilationResult,
    SourceDiagnostic,
    SourceLanguage,
    SourceStatus,
)
from claasp_next.representations.source.python import PYTHON_COMPILER, compile_python_source


def compile_source(primitive, *, target: SourceLanguage | str = SourceLanguage.PYTHON):
    """Compile a typed primitive to one explicitly selected source language.

    EXAMPLES::

        >>> from claasp_next.primitives import Speck
        >>> result = compile_source(Speck(32, 64, number_of_rounds=1), target="python")
        >>> result.is_ready
        True
        >>> result.artifact.filename
        'primitive_evaluator.py'
    """

    try:
        language = target if isinstance(target, SourceLanguage) else SourceLanguage(target)
    except (TypeError, ValueError):
        return SourceCompilationResult(
            SourceStatus.UNSUPPORTED,
            diagnostic=SourceDiagnostic(
                "unsupported_language", f"unsupported source language {target!r}"
            ),
        )
    if language is SourceLanguage.PYTHON:
        return compile_python_source(primitive)
    return compile_c_source(primitive)


__all__ = [
    "C_COMPILER",
    "PYTHON_COMPILER",
    "SourceArtifact",
    "SourceCompilationResult",
    "SourceDiagnostic",
    "SourceLanguage",
    "SourceStatus",
    "compile_c_source",
    "compile_python_source",
    "compile_source",
]
