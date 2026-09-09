"""Dependency-free sparse multivariate polynomials over prime fields."""

from collections.abc import Mapping
from dataclasses import dataclass

from claasp_next.domains import PrimeField


@dataclass(frozen=True, slots=True, order=True)
class Monomial:
    """A product represented by sorted ``(variable, exponent)`` pairs."""

    powers: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        names = []
        for name, exponent in self.powers:
            if not isinstance(name, str) or not name:
                raise ValueError("monomial variable names must be non-empty strings")
            if not isinstance(exponent, int) or isinstance(exponent, bool) or exponent <= 0:
                raise ValueError("monomial exponents must be positive integers")
            names.append(name)
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("monomial powers must have unique, sorted variable names")

    @classmethod
    def variable(cls, name: str) -> "Monomial":
        return cls(((name, 1),))

    @property
    def degree(self) -> int:
        return sum(exponent for _, exponent in self.powers)

    def __mul__(self, other: "Monomial") -> "Monomial":
        if not isinstance(other, Monomial):
            return NotImplemented
        powers = dict(self.powers)
        for name, exponent in other.powers:
            powers[name] = powers.get(name, 0) + exponent
        return Monomial(tuple(sorted(powers.items())))

    def __pow__(self, exponent: int) -> "Monomial":
        if not isinstance(exponent, int) or isinstance(exponent, bool) or exponent < 0:
            raise ValueError("monomial exponent must be a non-negative integer")
        if exponent == 0:
            return Monomial()
        return Monomial(tuple((name, power * exponent) for name, power in self.powers))

    def evaluate(self, values: Mapping[str, int], modulus: int) -> int:
        result = 1
        for name, exponent in self.powers:
            try:
                value = values[name]
            except KeyError as error:
                raise KeyError(f"value for polynomial variable {name!r} is missing") from error
            result = result * pow(value, exponent, modulus) % modulus
        return result


@dataclass(frozen=True, slots=True, init=False)
class Polynomial:
    """An immutable sparse polynomial over a
    :class:`~claasp_next.domains.prime_field.PrimeField`.

    Terms are normalized modulo the field modulus, zero coefficients are
    removed, and monomials are stored in deterministic order.

    EXAMPLES::

        >>> from claasp_next import PrimeField
        >>> from claasp_next.polynomial import Polynomial
        >>> field = PrimeField(17)
        >>> x = Polynomial.variable(field, "x")
        >>> polynomial = x**3 + 2 * x + 5
        >>> polynomial.degree
        3
        >>> polynomial.evaluate({"x": 4})
        9
    """

    field: PrimeField
    terms: tuple[tuple[Monomial, int], ...]

    def __init__(self, field: PrimeField, terms: Mapping[Monomial, int] | None = None) -> None:
        if not isinstance(field, PrimeField):
            raise TypeError("polynomial field must be a PrimeField")
        normalized: dict[Monomial, int] = {}
        for monomial, coefficient in (terms or {}).items():
            if not isinstance(monomial, Monomial):
                raise TypeError("polynomial term keys must be Monomial objects")
            if not isinstance(coefficient, int) or isinstance(coefficient, bool):
                raise TypeError("polynomial coefficients must be integers")
            reduced = coefficient % field.modulus
            if reduced:
                normalized[monomial] = reduced
        object.__setattr__(self, "field", field)
        object.__setattr__(self, "terms", tuple(sorted(normalized.items())))

    @classmethod
    def zero(cls, field: PrimeField) -> "Polynomial":
        return cls(field)

    @classmethod
    def constant(cls, field: PrimeField, value: int) -> "Polynomial":
        return cls(field, {Monomial(): value})

    @classmethod
    def variable(cls, field: PrimeField, name: str) -> "Polynomial":
        return cls(field, {Monomial.variable(name): 1})

    @property
    def degree(self) -> int:
        return max((monomial.degree for monomial, _ in self.terms), default=-1)

    def _coerce(self, other: object) -> "Polynomial":
        if isinstance(other, int) and not isinstance(other, bool):
            return Polynomial.constant(self.field, other)
        if not isinstance(other, Polynomial):
            raise TypeError(f"cannot combine Polynomial and {type(other).__name__}")
        if other.field != self.field:
            raise ValueError("polynomials must use the same coefficient field")
        return other

    def __add__(self, other: object) -> "Polynomial":
        other_polynomial = self._coerce(other)
        terms = dict(self.terms)
        for monomial, coefficient in other_polynomial.terms:
            terms[monomial] = terms.get(monomial, 0) + coefficient
        return Polynomial(self.field, terms)

    def __radd__(self, other: object) -> "Polynomial":
        return self + other

    def __neg__(self) -> "Polynomial":
        return Polynomial(self.field, {monomial: -coefficient for monomial, coefficient in self.terms})

    def __sub__(self, other: object) -> "Polynomial":
        return self + (-self._coerce(other))

    def __rsub__(self, other: object) -> "Polynomial":
        return self._coerce(other) - self

    def __mul__(self, other: object) -> "Polynomial":
        other_polynomial = self._coerce(other)
        terms: dict[Monomial, int] = {}
        for left_monomial, left_coefficient in self.terms:
            for right_monomial, right_coefficient in other_polynomial.terms:
                monomial = left_monomial * right_monomial
                terms[monomial] = terms.get(monomial, 0) + left_coefficient * right_coefficient
        return Polynomial(self.field, terms)

    def __rmul__(self, other: object) -> "Polynomial":
        return self * other

    def __pow__(self, exponent: int) -> "Polynomial":
        if not isinstance(exponent, int) or isinstance(exponent, bool) or exponent < 0:
            raise ValueError("polynomial exponent must be a non-negative integer")
        result = Polynomial.constant(self.field, 1)
        base = self
        remaining = exponent
        while remaining:
            if remaining & 1:
                result = result * base
            base = base * base
            remaining >>= 1
        return result

    def evaluate(self, values: Mapping[str, int]) -> int:
        return sum(
            coefficient * monomial.evaluate(values, self.field.modulus)
            for monomial, coefficient in self.terms
        ) % self.field.modulus
