"""Optional SAT-solver adapters."""

from claasp_next.boolean.solvers.base import SatResult, SatStatus
from claasp_next.boolean.solvers.minisat import MinisatSolver

__all__ = ["MinisatSolver", "SatResult", "SatStatus"]
