"""Backend containers for SAT constraint models."""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CNFFormula:
    """An immutable CNF formula with stable, human-readable variable names.

    Literals use the DIMACS convention: variable ``variables[i - 1]`` is
    represented by integer ``i`` and negation by ``-i``.


    EXAMPLES::

        >>> from dataclasses import fields
        >>> (CNFFormula.__dataclass_params__.frozen, tuple(field.name for field in fields(CNFFormula)))
        (True, ('variables', 'clauses', 'provenance'))
    """

    variables: tuple[str, ...]
    clauses: tuple[tuple[int, ...], ...]
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(set(self.variables)) != len(self.variables):
            raise ValueError("CNF variable names must be unique")
        if any(not name for name in self.variables):
            raise ValueError("CNF variable names must not be empty")
        if len(self.provenance) != len(self.clauses):
            raise ValueError("each CNF clause requires one provenance label")
        limit = len(self.variables)
        for clause in self.clauses:
            if not clause:
                raise ValueError("CNF clauses must not be empty")
            if any(literal == 0 or abs(literal) > limit for literal in clause):
                raise ValueError("CNF literal refers to an undeclared variable")

    @property
    def variable_count(self) -> int:
        """Return the variable count for this public typed contract."""

        return len(self.variables)

    @property
    def clause_count(self) -> int:
        """Return the clause count for this public typed contract."""

        return len(self.clauses)

    @property
    def literal_count(self) -> int:
        """Return the literal count for this public typed contract."""

        return sum(map(len, self.clauses))

    def is_satisfied(self, assignment: Mapping[str, int | bool]) -> bool:
        """Return whether a complete named assignment satisfies every clause."""

        missing = set(self.variables) - set(assignment)
        if missing:
            raise ValueError(f"assignment is missing CNF variables: {sorted(missing)!r}")
        values = []
        for name in self.variables:
            value = assignment[name]
            if value not in (0, 1, False, True):
                raise ValueError(f"CNF variable {name!r} must be Boolean")
            values.append(bool(value))
        return all(
            any(values[abs(literal) - 1] == (literal > 0) for literal in clause)
            for clause in self.clauses
        )


__all__ = ["CNFFormula"]
