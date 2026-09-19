"""Sparse Boolean polynomials and exact monomial-transition semantics."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class BooleanMonomial:
    """A square-free product of Boolean variables.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (BooleanMonomial.__dataclass_params__.frozen, tuple(field.name for field in fields(BooleanMonomial)))
        (True, ('variables',))
    """

    variables: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(not isinstance(name, str) or not name for name in self.variables):
            raise ValueError("Boolean variable names must be nonempty strings")
        if self.variables != tuple(sorted(set(self.variables))):
            raise ValueError("Boolean monomial variables must be unique and sorted")

    @classmethod
    def from_variables(cls, variables: Iterable[str]) -> "BooleanMonomial":
        """Compute the from variables for this public typed contract."""

        return cls(tuple(sorted(set(variables))))

    @property
    def degree(self) -> int:
        """Return the degree for this public typed contract."""

        return len(self.variables)

    def __mul__(self, other: "BooleanMonomial") -> "BooleanMonomial":
        if not isinstance(other, BooleanMonomial):
            return NotImplemented
        return BooleanMonomial.from_variables(self.variables + other.variables)


@dataclass(frozen=True, slots=True, init=False)
class BooleanPolynomial:
    """A dependency-free ANF represented by monomials with coefficient one.

    Addition is XOR and multiplication automatically applies ``x*x = x``.

    EXAMPLES::

        >>> x = BooleanPolynomial.variable("x")
        >>> y = BooleanPolynomial.variable("y")
        >>> polynomial = x * y + x + 1
        >>> [polynomial.evaluate({"x": a, "y": b}) for a in (0, 1) for b in (0, 1)]
        [1, 1, 0, 1]
    """

    monomials: tuple[BooleanMonomial, ...]

    def __init__(self, monomials: Iterable[BooleanMonomial] = ()) -> None:
        parity: set[BooleanMonomial] = set()
        for monomial in monomials:
            if not isinstance(monomial, BooleanMonomial):
                raise TypeError("ANF terms must be BooleanMonomial objects")
            if monomial in parity:
                parity.remove(monomial)
            else:
                parity.add(monomial)
        object.__setattr__(self, "monomials", tuple(sorted(parity)))

    @classmethod
    def zero(cls) -> "BooleanPolynomial":
        """Compute the zero for this public typed contract."""

        return cls()

    @classmethod
    def one(cls) -> "BooleanPolynomial":
        """Compute the one for this public typed contract."""

        return cls((BooleanMonomial(),))

    @classmethod
    def variable(cls, name: str) -> "BooleanPolynomial":
        """Compute the variable for this public typed contract."""

        return cls((BooleanMonomial((name,)),))

    @property
    def degree(self) -> int:
        """Return the degree for this public typed contract."""

        return max((monomial.degree for monomial in self.monomials), default=-1)

    def __add__(self, other: object) -> "BooleanPolynomial":
        if isinstance(other, int) and not isinstance(other, bool) and other in (0, 1):
            other = self.one() if other else self.zero()
        if not isinstance(other, BooleanPolynomial):
            return NotImplemented
        return BooleanPolynomial(self.monomials + other.monomials)

    __radd__ = __add__

    def __mul__(self, other: object) -> "BooleanPolynomial":
        if isinstance(other, int) and not isinstance(other, bool) and other in (0, 1):
            other = self.one() if other else self.zero()
        if not isinstance(other, BooleanPolynomial):
            return NotImplemented
        return BooleanPolynomial(
            left * right for left in self.monomials for right in other.monomials
        )

    __rmul__ = __mul__

    def evaluate(self, values: Mapping[str, int]) -> int:
        """Compute the evaluate for this public typed contract."""

        result = 0
        for monomial in self.monomials:
            term = 1
            for variable in monomial.variables:
                value = values[variable]
                if value not in (0, 1):
                    raise ValueError("Boolean assignments must contain only zero or one")
                term &= value
            result ^= term
        return result

    def cube_coefficient(self, cube: Iterable[str]) -> "BooleanPolynomial":
        """Return the symbolic coefficient of the selected cube monomial."""

        selected = frozenset(cube)
        if any(not isinstance(name, str) or not name for name in selected):
            raise ValueError("cube variables must be nonempty strings")
        return BooleanPolynomial(
            BooleanMonomial.from_variables(set(monomial.variables) - selected)
            for monomial in self.monomials
            if selected <= set(monomial.variables)
        )

    def substitute(self, values: Mapping[str, int]) -> "BooleanPolynomial":
        """Partially substitute Boolean constants while retaining other variables."""

        if any(value not in (0, 1) for value in values.values()):
            raise ValueError("Boolean substitutions must contain only zero or one")
        terms = []
        for monomial in self.monomials:
            if any(values.get(variable) == 0 for variable in monomial.variables):
                continue
            terms.append(
                BooleanMonomial.from_variables(
                    variable for variable in monomial.variables if variable not in values
                )
            )
        return BooleanPolynomial(terms)


def anf_from_truth_table(
    values: Sequence[int], variable_names: Sequence[str] | None = None
) -> BooleanPolynomial:
    """Compute an exact ANF by the in-place Möbius transform.

    EXAMPLES::

        >>> try:
        ...     anf_from_truth_table()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    size = len(values)
    if size < 2 or size & (size - 1):
        raise ValueError("truth-table length must be a power of two")
    if any(value not in (0, 1) for value in values):
        raise ValueError("truth-table entries must be zero or one")
    width = size.bit_length() - 1
    names = tuple(variable_names or (f"x{index}" for index in range(width)))
    if len(names) != width or len(set(names)) != width:
        raise ValueError("variable names must be unique and match the table width")
    coefficients = list(values)
    for bit in range(width):
        for mask in range(size):
            if mask & (1 << bit):
                coefficients[mask] ^= coefficients[mask ^ (1 << bit)]
    return BooleanPolynomial(
        BooleanMonomial.from_variables(
            names[width - 1 - bit] for bit in range(width) if mask & (1 << bit)
        )
        for mask, coefficient in enumerate(coefficients)
        if coefficient
    )


def vectorial_anf(
    table: Sequence[int], variable_names: Sequence[str] | None = None
) -> tuple[BooleanPolynomial, ...]:
    """Return output-bit ANFs of a power-of-two lookup table, MSB first.

    EXAMPLES::

        >>> try:
        ...     vectorial_anf()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    size = len(table)
    if size < 2 or size & (size - 1):
        raise ValueError("lookup-table length must be a power of two")
    width = size.bit_length() - 1
    if any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < size
        for value in table
    ):
        raise ValueError("lookup-table outputs must fit its input width")
    return tuple(
        anf_from_truth_table(tuple((value >> bit) & 1 for value in table), variable_names)
        for bit in reversed(range(width))
    )


def monomial_transition_table(table: Sequence[int]) -> dict[int, frozenset[int]]:
    """Return the exact 3-subset-division-property transition table.

    Each output mask maps to the input masks whose monomials occur in the
    product of the selected output-bit ANFs. This replaces the Gurobi/Sage
    table builder for small substitution components.


    EXAMPLES::

        >>> try:
        ...     monomial_transition_table()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    width = len(table).bit_length() - 1
    names = tuple(f"x{index}" for index in range(width))
    positions = {name: index for index, name in enumerate(names)}
    output_anfs = vectorial_anf(table, names)
    result: dict[int, frozenset[int]] = {}
    for output_mask in range(1 << width):
        product = BooleanPolynomial.one()
        for index, polynomial in enumerate(output_anfs):
            if output_mask & (1 << (width - 1 - index)):
                product *= polynomial
        result[output_mask] = frozenset(
            sum(1 << (width - 1 - positions[name]) for name in monomial.variables)
            for monomial in product.monomials
        )
    return result


def equality_polynomials(
    left: Sequence[BooleanPolynomial],
    right: Sequence[BooleanPolynomial],
) -> tuple[BooleanPolynomial, ...]:
    """Return equations enforcing equality of two Boolean vectors.

    Each returned polynomial is interpreted as equal to zero.

    EXAMPLES::

        >>> x = tuple(BooleanPolynomial.variable(f"x{i}") for i in range(2))
        >>> y = tuple(BooleanPolynomial.variable(f"y{i}") for i in range(2))
        >>> equations = equality_polynomials(x, y)
        >>> tuple(equation.evaluate({"x0": 1, "x1": 0, "y0": 1, "y1": 0}) for equation in equations)
        (0, 0)
    """

    left = _boolean_vector("left", left)
    right = _boolean_vector("right", right)
    if len(left) != len(right):
        raise ValueError("left and right must have equal lengths")
    return tuple(x + y for x, y in zip(left, right))


def modular_addition_polynomials(
    left: Sequence[BooleanPolynomial],
    right: Sequence[BooleanPolynomial],
    output: Sequence[BooleanPolynomial],
    carries: Sequence[BooleanPolynomial] | None = None,
) -> tuple[BooleanPolynomial, ...]:
    """Return exact equations for binary modular addition.

    Vectors are ordered least-significant bit first, matching the recurrence
    for a ripple carry.  Supplying ``carries`` exposes the carry variables;
    omitting it substitutes their exact ANFs into the output equations.

    EXAMPLES::

        >>> x = tuple(BooleanPolynomial.variable(f"x{i}") for i in range(3))
        >>> y = tuple(BooleanPolynomial.variable(f"y{i}") for i in range(3))
        >>> z = tuple(BooleanPolynomial.variable(f"z{i}") for i in range(3))
        >>> equations = modular_addition_polynomials(x, y, z)
        >>> values = {"x0": 1, "x1": 1, "x2": 0, "y0": 1, "y1": 0, "y2": 1,
        ...           "z0": 0, "z1": 0, "z2": 0}
        >>> tuple(equation.evaluate(values) for equation in equations)
        (0, 0, 0)
    """

    return _modular_binary_polynomials(left, right, output, carries, subtract=False)


def modular_subtraction_polynomials(
    left: Sequence[BooleanPolynomial],
    right: Sequence[BooleanPolynomial],
    output: Sequence[BooleanPolynomial],
    borrows: Sequence[BooleanPolynomial] | None = None,
) -> tuple[BooleanPolynomial, ...]:
    """Return exact equations for ``left - right`` modulo ``2**width``.

    Vectors and optional borrow variables are least-significant bit first.
    As with addition, omitting ``borrows`` eliminates them by substitution.


    EXAMPLES::

        >>> try:
        ...     modular_subtraction_polynomials()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    return _modular_binary_polynomials(left, right, output, borrows, subtract=True)


def _modular_binary_polynomials(left, right, output, auxiliaries, *, subtract):
    left = _boolean_vector("left", left)
    right = _boolean_vector("right", right)
    output = _boolean_vector("output", output)
    if not left:
        raise ValueError("Boolean vectors must be nonempty")
    if len(left) != len(right) or len(left) != len(output):
        raise ValueError("left, right, and output must have equal lengths")

    if auxiliaries is None:
        carry = BooleanPolynomial.zero()
        equations = []
        for x, y, z in zip(left, right, output):
            equations.append(x + y + z + carry)
            carry = _next_auxiliary(x, y, carry, subtract=subtract)
        return tuple(equations)

    auxiliaries = _boolean_vector("carries" if not subtract else "borrows", auxiliaries)
    if len(auxiliaries) != len(left):
        name = "carries" if not subtract else "borrows"
        raise ValueError(f"{name} must have the same length as the operands")
    equations = [auxiliaries[0]]
    for index, (x, y, z, carry) in enumerate(zip(left, right, output, auxiliaries)):
        equations.append(x + y + z + carry)
        if index + 1 < len(auxiliaries):
            equations.append(
                _next_auxiliary(x, y, carry, subtract=subtract) + auxiliaries[index + 1]
            )
    return tuple(equations)


def _next_auxiliary(x, y, carry, *, subtract):
    result = x * y + x * carry + y * carry
    if subtract:
        result += y + carry
    return result


def _boolean_vector(name, values):
    values = tuple(values)
    if any(not isinstance(value, BooleanPolynomial) for value in values):
        raise TypeError(f"{name} must contain BooleanPolynomial objects")
    return values
