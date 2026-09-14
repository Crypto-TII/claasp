"""Sage/Gurobi-free ANF, superpoly, and monomial-transition regressions."""

from claasp_next.representations.constraints.polynomial import (
    BooleanPolynomial, anf_from_truth_table, monomial_transition_table,
    vectorial_anf,
)
from claasp_next.representations.constraints.milp import MonomialTransitionMILPModel


PRESENT = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)


def test_present_vectorial_anf_matches_every_legacy_sbox_value():
    anfs = vectorial_anf(PRESENT, ("p0", "p1", "p2", "p3"))

    for value, expected in enumerate(PRESENT):
        assignment = {f"p{index}": (value >> (3 - index)) & 1 for index in range(4)}
        computed = sum(polynomial.evaluate(assignment) << (3 - index) for index, polynomial in enumerate(anfs))
        assert computed == expected


def test_mobius_transform_preserves_a_fixed_legacy_style_anf():
    # f(p0,p1,p2) = p0*p1 + p0 + p2 + 1
    values = tuple(((x >> 2) & 1) * ((x >> 1) & 1) ^ ((x >> 2) & 1) ^ (x & 1) ^ 1 for x in range(8))
    polynomial = anf_from_truth_table(values, ("p0", "p1", "p2"))

    assert polynomial.degree == 2
    assert {term.variables for term in polynomial.monomials} == {(), ("p0",), ("p2",), ("p0", "p1")}


def test_cube_coefficient_returns_a_symbolic_superpoly_with_parity():
    p0 = BooleanPolynomial.variable("p0")
    p9 = BooleanPolynomial.variable("p9")
    k1 = BooleanPolynomial.variable("k1")
    k2 = BooleanPolynomial.variable("k2")
    k49 = BooleanPolynomial.variable("k49")
    polynomial = p0 * p9 * k49 + p0 * p9 * k1 * k2 + p0 * k1 + p0 * p9 * k49

    # The duplicate k49 term cancels over GF(2).
    assert polynomial.cube_coefficient(("p0", "p9")) == k1 * k2


def test_exact_monomial_transition_table_matches_direct_anf_products():
    table = monomial_transition_table(PRESENT)
    anfs = vectorial_anf(PRESENT)

    assert table[0] == frozenset({0})
    for output_mask, input_masks in table.items():
        product = BooleanPolynomial.one()
        for index, anf in enumerate(anfs):
            if output_mask & (1 << (3 - index)):
                product *= anf
        direct = frozenset(
            sum(1 << (3 - int(name[1:])) for name in monomial.variables)
            for monomial in product.monomials
        )
        assert input_masks == direct


def test_portable_milp_representation_selects_exact_monomial_transition():
    representation = MonomialTransitionMILPModel(PRESENT)
    output_mask = 1
    input_mask = min(monomial_transition_table(PRESENT)[output_mask])
    assignment = representation.assignment(input_mask, output_mask)

    assert representation.milp_model().is_feasible(assignment)
    impossible = next(mask for mask in range(16) if mask not in representation.table[output_mask])
    try:
        representation.assignment(impossible, output_mask)
    except ValueError as error:
        assert "impossible" in str(error)
    else:
        raise AssertionError("an impossible monomial transition was accepted")
