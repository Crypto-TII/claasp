"""Optional external constraint-solver drivers."""

from claasp_next.drivers.solvers.base import SatResult, SatStatus
from claasp_next.drivers.solvers.minisat import MinisatSolver
from claasp_next.drivers.solvers.milp_results import MILPResult, MILPStatus

__all__ = [
    "GLPKSolver", "MILPResult", "MILPStatus", "MinisatSolver", "SatResult",
    "SatStatus", "Z3Solver",
]


def __getattr__(name: str):
    """Load representation-specific drivers without creating import cycles."""

    if name == "Z3Solver":
        from claasp_next.drivers.solvers.z3 import Z3Solver

        return Z3Solver
    if name == "GLPKSolver":
        from claasp_next.drivers.solvers.glpk import GLPKSolver

        return GLPKSolver
    raise AttributeError(name)
