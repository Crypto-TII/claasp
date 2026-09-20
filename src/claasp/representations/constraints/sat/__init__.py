"""Dependency-free Boolean/CNF constraint representations."""

from claasp.representations.constraints.sat.cnf import CNFFormula
from claasp.representations.constraints.sat.lowering import BooleanCNFModel

__all__ = ["BooleanCNFModel", "CNFFormula"]
