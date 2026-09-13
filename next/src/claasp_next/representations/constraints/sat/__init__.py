"""Dependency-free Boolean/CNF constraint representations."""

from claasp_next.representations.constraints.sat.cnf import CNFFormula
from claasp_next.representations.constraints.sat.lowering import BooleanCNFModel

__all__ = ["BooleanCNFModel", "CNFFormula"]
