"""Results returned by external computer-algebra drivers."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AlgebraExecutionResult:
    """Captured output from a successfully completed algebra-system process.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (AlgebraExecutionResult.__dataclass_params__.frozen, tuple(field.name for field in fields(AlgebraExecutionResult)))
        (True, ('stdout', 'stderr', 'runtime_seconds', 'result_text'))
    """

    stdout: str
    stderr: str
    runtime_seconds: float
    result_text: str | None = None
