"""Backend-neutral constraint-solver result types."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class SatStatus(str, Enum):
    """Portable outcome of a SAT solver invocation."""

    SATISFIABLE = "satisfiable"
    UNSATISFIABLE = "unsatisfiable"


@dataclass(frozen=True, slots=True)
class SatResult:
    """A SAT status and, when satisfiable, its named assignment."""

    status: SatStatus
    assignment: Mapping[str, int] | None
    runtime_seconds: float
    stdout: str
    stderr: str

    @property
    def is_satisfiable(self) -> bool:
        """Whether the solver returned a satisfying assignment."""

        return self.status is SatStatus.SATISFIABLE
