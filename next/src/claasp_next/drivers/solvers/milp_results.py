"""Backend-neutral MILP driver result types."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class MILPStatus(str, Enum):
    """Portable outcome of a linear optimization invocation.

    EXAMPLES::

        >>> tuple(member.value for member in MILPStatus)
        ('optimal', 'feasible', 'infeasible', 'unknown')
    """

    OPTIMAL = "optimal"
    FEASIBLE = "feasible"
    INFEASIBLE = "infeasible"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class MILPResult:
    """Optimization status, objective, and named primal assignment.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MILPResult.__dataclass_params__.frozen, tuple(field.name for field in fields(MILPResult)))
        (True, ('status', 'assignment', 'objective_value', 'runtime_seconds', 'stdout', 'stderr'))
    """

    status: MILPStatus
    assignment: Mapping[str, float] | None
    objective_value: float | None
    runtime_seconds: float
    stdout: str
    stderr: str

    @property
    def is_feasible(self) -> bool:
        """Whether the solver returned a primal witness."""

        return self.status in (MILPStatus.OPTIMAL, MILPStatus.FEASIBLE)
