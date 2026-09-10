"""Dependency-free Boolean models and solver interchange formats."""

from claasp_next.boolean.cnf import CNFFormula
from claasp_next.boolean.lowering import BooleanCNFModel

__all__ = ["BooleanCNFModel", "CNFFormula"]
