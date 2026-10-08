"""Dependency-free Boolean/CNF constraint representations."""

from claasp.representations.constraints.sat.cnf import CNFFormula
from claasp.representations.constraints.sat.lowering import BooleanCNFModel

__all__ = [
    "BooleanCNFModel",
    "CNFFormula",
    "WordDifferentialSATModel",
    "WordLinearSATModel",
]


def __getattr__(name):
    if name in ("WordDifferentialSATModel", "WordLinearSATModel"):
        from claasp.representations.constraints.sat import trails

        value = getattr(trails, name)
        globals()[name] = value
        return value
    raise AttributeError(name)
