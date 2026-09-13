"""Results returned by external computer-algebra drivers."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AlgebraExecutionResult:
    """Captured output from a successfully completed algebra-system process."""

    stdout: str
    stderr: str
    runtime_seconds: float
    result_text: str | None = None
