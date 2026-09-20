"""A minimal solver-independent Boolean SMT representation."""

from dataclasses import dataclass

from claasp.representations.constraints.sat import CNFFormula


@dataclass(frozen=True, slots=True)
class SMTFormula:
    """Named Boolean declarations and disjunctive assertions.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SMTFormula.__dataclass_params__.frozen, tuple(field.name for field in fields(SMTFormula)))
        (True, ('variables', 'assertions', 'provenance'))
    """

    variables: tuple[str, ...]
    assertions: tuple[tuple[int, ...], ...]
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        CNFFormula(self.variables, self.assertions, self.provenance)

    @classmethod
    def from_cnf(cls, formula: CNFFormula) -> "SMTFormula":
        """Translate a Boolean CNF without changing its logical semantics."""

        if not isinstance(formula, CNFFormula):
            raise TypeError("formula must be a CNFFormula")
        return cls(formula.variables, formula.clauses, formula.provenance)

    @property
    def assertion_count(self) -> int:
        """Return the assertion count for this public typed contract."""

        return len(self.assertions)
