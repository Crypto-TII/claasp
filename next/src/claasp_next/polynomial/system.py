"""Polynomial systems with equation provenance."""

from dataclasses import dataclass

from claasp_next.domains import PrimeField
from claasp_next.polynomial.expression import Polynomial


@dataclass(frozen=True, slots=True)
class PolynomialSystem:
    """An ordered system of equations interpreted as ``equation == 0``."""

    field: PrimeField
    variables: tuple[str, ...]
    equations: tuple[Polynomial, ...]
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.field, PrimeField):
            raise TypeError("system field must be a PrimeField")
        if len(self.equations) != len(self.provenance):
            raise ValueError("every equation must have one provenance entry")
        if len(self.variables) != len(set(self.variables)):
            raise ValueError("system variable names must be unique")
        if any(equation.field != self.field for equation in self.equations):
            raise ValueError("every equation must use the system coefficient field")

    @property
    def maximum_degree(self) -> int:
        return max((equation.degree for equation in self.equations), default=-1)

    def evaluate(self, values: dict[str, int]) -> tuple[int, ...]:
        """Evaluate every left-hand side in equation order."""

        return tuple(equation.evaluate(values) for equation in self.equations)
