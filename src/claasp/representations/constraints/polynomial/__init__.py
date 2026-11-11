"""Sage-independent polynomial constraint representations and lowering."""

from claasp._catalogue_metadata import _entry
from claasp.representations.constraints.polynomial.boolean import (
    BooleanMonomial,
    BooleanPolynomial,
    anf_from_truth_table,
    equality_polynomials,
    modular_addition_polynomials,
    modular_subtraction_polynomials,
    monomial_transition_table,
    vectorial_anf,
)
from claasp.representations.constraints.polynomial.boolean_system import BooleanEquationSystem
from claasp.representations.constraints.polynomial.expression import Monomial, Polynomial
from claasp.representations.constraints.polynomial.lowering import (
    PowerLoweringPolicy,
    PrimeFieldPolynomialModel,
)
from claasp.representations.constraints.polynomial.system import (
    PolynomialSystem,
    PolynomialSystemStatistics,
)

__all__ = [
    "BooleanEquationSystem",
    "BooleanMonomial",
    "BooleanPolynomial",
    "Monomial",
    "Polynomial",
    "PolynomialSystem",
    "PolynomialSystemStatistics",
    "PowerLoweringPolicy",
    "PrimeFieldPolynomialModel",
    "anf_from_truth_table",
    "equality_polynomials",
    "modular_addition_polynomials",
    "modular_subtraction_polynomials",
    "monomial_transition_table",
    "vectorial_anf",
]


__catalogue__ = (
    _entry(
        "representation",
        PrimeFieldPolynomialModel,
        name="prime_field_polynomial",
        kind="constraint",
        components=("Add", "Constant", "Identity", "LinearMap", "Multiply", "Permutation", "Power"),
        domains=("PrimeField",),
        drivers=(),
        scope="generic_graph",
    ),
)
