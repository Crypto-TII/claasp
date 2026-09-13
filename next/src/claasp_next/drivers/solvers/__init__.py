"""Optional external constraint-solver drivers."""

from claasp_next.drivers.solvers.base import SatResult, SatStatus
from claasp_next.drivers.solvers.minisat import MinisatSolver

__all__ = ["MinisatSolver", "SatResult", "SatStatus", "Z3Solver"]


def __getattr__(name: str):
    """Load representation-specific drivers without creating import cycles."""

    if name == "Z3Solver":
        from claasp_next.drivers.solvers.z3 import Z3Solver

        return Z3Solver
    raise AttributeError(name)
