"""Backend containers for SAT constraint models."""

from collections.abc import Mapping
from dataclasses import dataclass

from claasp.representations.constraints import ConstraintModelApplication


@dataclass(frozen=True, slots=True)
class CNFFormula:
    """An immutable CNF formula with stable, human-readable variable names.

    Literals use the DIMACS convention: variable ``variables[i - 1]`` is
    represented by integer ``i`` and negation by ``-i``.


    EXAMPLES::

        >>> from dataclasses import fields
        >>> (CNFFormula.__dataclass_params__.frozen, tuple(field.name for field in fields(CNFFormula)))
        (True, ('variables', 'clauses', 'provenance', 'constraint_models'))
    """

    variables: tuple[str, ...]
    clauses: tuple[tuple[int, ...], ...]
    provenance: tuple[str, ...]
    constraint_models: tuple[ConstraintModelApplication, ...] = ()

    def __post_init__(self) -> None:
        if len(set(self.variables)) != len(self.variables):
            raise ValueError("CNF variable names must be unique")
        if any(not name for name in self.variables):
            raise ValueError("CNF variable names must not be empty")
        if len(self.provenance) != len(self.clauses):
            raise ValueError("each CNF clause requires one provenance label")
        if any(not isinstance(item, ConstraintModelApplication) for item in self.constraint_models):
            raise TypeError("constraint_models must contain ConstraintModelApplication values")
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


@dataclass(frozen=True, slots=True)
class NativeXorCNFFormula(CNFFormula):
    """CNF plus parity clauses accepted natively by CryptoMiniSat.

    Each XOR clause requires the XOR of its signed literal truth values to be
    true. Ordinary CNF remains available for components without a native form.

    EXAMPLES::

        >>> formula = NativeXorCNFFormula(
        ...     ("a", "b", "y"), (), (), (), ((1, 2, -3),), ("xor",)
        ... )
        >>> formula.is_satisfied({"a": 1, "b": 0, "y": 1})
        True
        >>> formula.is_satisfied({"a": 1, "b": 1, "y": 1})
        False
    """

    xor_clauses: tuple[tuple[int, ...], ...] = ()
    xor_provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(NativeXorCNFFormula, self).__post_init__()
        if len(self.xor_clauses) != len(self.xor_provenance):
            raise ValueError("each native XOR clause requires one provenance label")
        limit = len(self.variables)
        for clause in self.xor_clauses:
            if not clause:
                raise ValueError("native XOR clauses must not be empty")
            if any(literal == 0 or abs(literal) > limit for literal in clause):
                raise ValueError("native XOR literal refers to an undeclared variable")

    @property
    def native_xor_count(self) -> int:
        """Return the number of native parity constraints."""

        return len(self.xor_clauses)

    def is_satisfied(self, assignment: Mapping[str, int | bool]) -> bool:
        """Check ordinary clauses and native signed-literal parity."""

        if not CNFFormula.is_satisfied(self, assignment):
            return False
        values = tuple(bool(assignment[name]) for name in self.variables)
        return all(
            sum(values[abs(literal) - 1] == (literal > 0) for literal in clause) % 2 == 1
            for clause in self.xor_clauses
        )

    def expanded_cnf(self) -> CNFFormula:
        """Expand every parity record to equivalent ordinary CNF.

        This is an independent portability oracle, not the native-XOR path.
        """

        clauses = list(self.clauses)
        provenance = list(self.provenance)
        for xor_clause, label in zip(self.xor_clauses, self.xor_provenance):
            indices = tuple(abs(literal) for literal in xor_clause)
            if len(set(indices)) != len(indices):
                raise ValueError("native XOR clauses must not repeat a variable")
            for assignment in range(1 << len(xor_clause)):
                bits = tuple(
                    (assignment >> (len(xor_clause) - 1 - bit)) & 1
                    for bit in range(len(xor_clause))
                )
                literal_truth = tuple(
                    bool(value) == (literal > 0) for value, literal in zip(bits, xor_clause)
                )
                if sum(literal_truth) % 2 == 1:
                    continue
                clauses.append(
                    tuple(-index if value else index for index, value in zip(indices, bits))
                )
                provenance.append(label)
        return CNFFormula(
            self.variables,
            tuple(clauses),
            tuple(provenance),
            self.constraint_models,
        )


__all__ = ["CNFFormula", "NativeXorCNFFormula"]
