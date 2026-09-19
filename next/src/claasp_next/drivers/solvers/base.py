"""Backend-neutral constraint-solver result types."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class SatStatus(str, Enum):
    """Portable outcome of a SAT solver invocation.

    EXAMPLES::

        >>> tuple(member.value for member in SatStatus)
        ('satisfiable', 'unsatisfiable')
    """

    SATISFIABLE = "satisfiable"
    UNSATISFIABLE = "unsatisfiable"


@dataclass(frozen=True, slots=True)
class SatResult:
    """A SAT status and, when satisfiable, its named assignment.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SatResult.__dataclass_params__.frozen, tuple(field.name for field in fields(SatResult)))
        (True, ('status', 'assignment', 'runtime_seconds', 'stdout', 'stderr'))
    """

    status: SatStatus
    assignment: Mapping[str, int] | None
    runtime_seconds: float
    stdout: str
    stderr: str

    @property
    def is_satisfiable(self) -> bool:
        """Whether the solver returned a satisfying assignment."""

        return self.status is SatStatus.SATISFIABLE
