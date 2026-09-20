"""Sage-independent Boolean polynomial constraint regressions."""

from itertools import product

import pytest

from claasp.representations.constraints.polynomial import (
    BooleanPolynomial,
    equality_polynomials,
    modular_addition_polynomials,
    modular_subtraction_polynomials,
)


def _variables(prefix, width):
    return tuple(BooleanPolynomial.variable(f"{prefix}{index}") for index in range(width))


def _assignment(width, left, right, output, *, auxiliary=None):
    values = {}
    for prefix, number in (("x", left), ("y", right), ("z", output)):
        values.update({f"{prefix}{index}": (number >> index) & 1 for index in range(width)})
    if auxiliary is not None:
        values.update({f"c{index}": value for index, value in enumerate(auxiliary)})
    return values


def test_equality_polynomials_preserve_vector_equality_semantics():
    x = _variables("x", 3)
    y = _variables("y", 3)
    equations = equality_polynomials(x, y)

    for left, right in product(range(8), repeat=2):
        assignment = {
            **{f"x{i}": (left >> i) & 1 for i in range(3)},
            **{f"y{i}": (right >> i) & 1 for i in range(3)},
        }
        assert all(equation.evaluate(assignment) == 0 for equation in equations) == (left == right)


@pytest.mark.parametrize(
    ("factory", "operation"),
    (
        (modular_addition_polynomials, lambda left, right: left + right),
        (modular_subtraction_polynomials, lambda left, right: left - right),
    ),
)
def test_eliminated_ripple_equations_exhaustively_match_modular_arithmetic(factory, operation):
    width = 4
    x, y, z = (_variables(prefix, width) for prefix in "xyz")
    equations = factory(x, y, z)

    for left, right, candidate in product(range(1 << width), repeat=3):
        satisfies = all(
            equation.evaluate(_assignment(width, left, right, candidate)) == 0
            for equation in equations
        )
        assert satisfies == (candidate == operation(left, right) % (1 << width))


@pytest.mark.parametrize(
    ("factory", "subtract"),
    ((modular_addition_polynomials, False), (modular_subtraction_polynomials, True)),
)
def test_explicit_auxiliary_equations_preserve_legacy_ripple_structure(factory, subtract):
    width = 4
    x, y, z, c = (_variables(prefix, width) for prefix in "xyzc")
    equations = factory(x, y, z, c)

    assert len(equations) == 2 * width
    for left, right in product(range(1 << width), repeat=2):
        output = (left - right if subtract else left + right) % (1 << width)
        carry = 0
        auxiliaries = []
        for index in range(width):
            auxiliaries.append(carry)
            left_bit = (left >> index) & 1
            right_bit = (right >> index) & 1
            if subtract:
                carry = int(left_bit - right_bit - carry < 0)
            else:
                carry = int(left_bit + right_bit + carry >= 2)
        assignment = _assignment(width, left, right, output, auxiliary=auxiliaries)
        assert all(equation.evaluate(assignment) == 0 for equation in equations)


def test_boolean_constraint_vectors_are_validated():
    x = _variables("x", 2)
    with pytest.raises(ValueError, match="equal lengths"):
        equality_polynomials(x, x[:1])
    with pytest.raises(ValueError, match="nonempty"):
        modular_addition_polynomials((), (), ())
    with pytest.raises(ValueError, match="same length"):
        modular_subtraction_polynomials(x, x, x, _variables("c", 1))
    with pytest.raises(TypeError, match="BooleanPolynomial"):
        equality_polynomials(x, (0, 1))
