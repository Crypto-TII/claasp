"""Backend containers for SMT constraint models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from claasp.representations.constraints import ConstraintModelApplication

if TYPE_CHECKING:
    from claasp.representations.constraints.sat.model import CNFFormula


@dataclass(frozen=True, slots=True)
class SMTFormula:
    """Named Boolean declarations and disjunctive assertions.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SMTFormula.__dataclass_params__.frozen, tuple(field.name for field in fields(SMTFormula)))
        (True, ('variables', 'assertions', 'provenance', 'constraint_models'))
    """

    variables: tuple[str, ...]
    assertions: tuple[tuple[int, ...], ...]
    provenance: tuple[str, ...]
    constraint_models: tuple[ConstraintModelApplication, ...] = ()

    def __post_init__(self) -> None:
        if len(set(self.variables)) != len(self.variables):
            raise ValueError("SMT variable names must be unique")
        if any(not name for name in self.variables):
            raise ValueError("SMT variable names must not be empty")
        if len(self.provenance) != len(self.assertions):
            raise ValueError("each SMT assertion requires one provenance label")
        if any(not isinstance(item, ConstraintModelApplication) for item in self.constraint_models):
            raise TypeError("constraint_models must contain ConstraintModelApplication values")
        limit = len(self.variables)
        for assertion in self.assertions:
            if not assertion:
                raise ValueError("SMT assertions must not be empty")
            if any(literal == 0 or abs(literal) > limit for literal in assertion):
                raise ValueError("SMT literal refers to an undeclared variable")

    @classmethod
    def from_cnf(cls, formula: CNFFormula) -> "SMTFormula":
        """Translate a Boolean CNF without changing its logical semantics."""

        from claasp.representations.constraints.sat.model import CNFFormula

        if not isinstance(formula, CNFFormula):
            raise TypeError("formula must be a CNFFormula")
        return cls(
            formula.variables,
            formula.clauses,
            formula.provenance,
            formula.constraint_models,
        )

    @property
    def assertion_count(self) -> int:
        """Return the assertion count for this public typed contract."""

        return len(self.assertions)


__all__ = ["SMTFormula"]
