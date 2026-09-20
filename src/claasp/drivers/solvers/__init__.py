"""Optional external constraint-solver drivers."""

from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp.drivers.solvers.minisat import MinisatSolver
from claasp.drivers.solvers.minizinc import (
    CPEnumerationResult,
    CPResult,
    CPStatus,
    MiniZincSolver,
)

__all__ = [
    "CPEnumerationResult",
    "CPResult",
    "CPStatus",
    "GLPKSolver",
    "MILPResult",
    "MILPStatus",
    "MiniZincSolver",
    "MinisatSolver",
    "SatResult",
    "SatStatus",
    "Z3Solver",
]


def __getattr__(name: str):
    """Load representation-specific drivers without creating import cycles."""

    if name == "Z3Solver":
        from claasp.drivers.solvers.z3 import Z3Solver

        return Z3Solver
    if name == "GLPKSolver":
        from claasp.drivers.solvers.glpk import GLPKSolver

        return GLPKSolver
    raise AttributeError(name)
