"""Polynomial-system representations with equation provenance."""

from dataclasses import dataclass

from claasp_next.domains import PrimeField
from claasp_next.representations.constraints.polynomial.expression import Polynomial


@dataclass(frozen=True, slots=True)
class PolynomialSystemStatistics:
    """Structural statistics for comparing lowering policies.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PolynomialSystemStatistics.__dataclass_params__.frozen, tuple(field.name for field in fields(PolynomialSystemStatistics)))
        (True, ('variable_count', 'equation_count', 'term_count', 'maximum_degree', 'degree_histogram', 'variable_incidence'))
    """

    variable_count: int
    equation_count: int
    term_count: int
    maximum_degree: int
    degree_histogram: tuple[tuple[int, int], ...]
    variable_incidence: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class PolynomialSystem:
    """An ordered system of equations interpreted as ``equation == 0``.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PolynomialSystem.__dataclass_params__.frozen, tuple(field.name for field in fields(PolynomialSystem)))
        (True, ('field', 'variables', 'equations', 'provenance'))
    """

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
        """Return the maximum degree for this public typed contract."""

        return max((equation.degree for equation in self.equations), default=-1)

    def evaluate(self, values: dict[str, int]) -> tuple[int, ...]:
        """Evaluate every left-hand side in equation order."""

        return tuple(equation.evaluate(values) for equation in self.equations)

    @property
    def statistics(self) -> PolynomialSystemStatistics:
        """Return deterministic size, degree, and incidence statistics."""

        degrees: dict[int, int] = {}
        incidence = {variable: 0 for variable in self.variables}
        term_count = 0
        for equation in self.equations:
            degrees[equation.degree] = degrees.get(equation.degree, 0) + 1
            term_count += len(equation.terms)
            present = {
                variable for monomial, _ in equation.terms for variable, _ in monomial.powers
            }
            for variable in present:
                if variable in incidence:
                    incidence[variable] += 1
        return PolynomialSystemStatistics(
            variable_count=len(self.variables),
            equation_count=len(self.equations),
            term_count=term_count,
            maximum_degree=self.maximum_degree,
            degree_histogram=tuple(sorted(degrees.items())),
            variable_incidence=tuple(incidence.items()),
        )
