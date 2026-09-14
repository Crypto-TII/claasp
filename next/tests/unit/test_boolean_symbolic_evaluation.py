"""Exact graph ANF recovery without Sage or Gurobi."""

from claasp_next.primitives import Simon
from claasp_next.representations.constraints.polynomial import BooleanMonomial
from claasp_next.representations.execution import BooleanSymbolicEvaluator


def test_one_round_simon_anf_preserves_legacy_fixed_monomials():
    result = BooleanSymbolicEvaluator().evaluate(Simon(number_of_rounds=1))
    first_output = result.output_anfs[0]
    terms = set(first_output.monomials)

    assert terms == {
        BooleanMonomial(("k48",)), BooleanMonomial(("p1", "p8")),
        BooleanMonomial(("p16",)), BooleanMonomial(("p2",)),
    }
    assert first_output.degree == 2


def test_symbolic_simon_anf_evaluates_like_the_typed_primitive():
    primitive = Simon(number_of_rounds=1)
    result = BooleanSymbolicEvaluator().evaluate(primitive)
    plaintext = 0x12345678
    key = 0x1918111009080100
    assignment = {
        **{f"p{index}": (plaintext >> (31 - index)) & 1 for index in range(32)},
        **{f"k{index}": (key >> (63 - index)) & 1 for index in range(64)},
    }
    symbolic = sum(polynomial.evaluate(assignment) << (31 - index)
                   for index, polynomial in enumerate(result.output_anfs))

    assert symbolic == primitive.evaluate(plaintext, key)


def test_two_round_simon_degrees_and_superpoly_preserve_legacy_results():
    result = BooleanSymbolicEvaluator().evaluate(Simon(number_of_rounds=2))

    assert [polynomial.degree for polynomial in result.output_anfs] == [3] * 16 + [2] * 16
    partial = result.output_anfs[0].cube_coefficient(("p0", "p9"))
    noncube_plaintext = {f"p{index}": 0 for index in range(32) if index not in (0, 9)}
    superpoly = partial.substitute(noncube_plaintext)
    assert superpoly.monomials == (BooleanMonomial(("k49",)),)
