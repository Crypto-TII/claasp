import pytest

from claasp_next import Bit, Cipher, PrimeField, ScalarEvaluator, ValueType
from claasp_next.ciphers import MiMCPermutation, PoseidonPermutation
from claasp_next.polynomial import Monomial, Polynomial, PrimeFieldPolynomialModel


def _assignment_from_evaluation(result):
    return {
        f"{source_id}_{position}": value
        for source_id, source_value in result.values.items()
        for position, value in enumerate(source_value)
    }


def test_sparse_polynomial_arithmetic_is_normalized():
    field = PrimeField(17)
    x = Polynomial.variable(field, "x")
    y = Polynomial.variable(field, "y")

    polynomial = (x + y) * (x - y) + 17 * x

    assert polynomial.degree == 2
    assert polynomial.evaluate({"x": 4, "y": 3}) == 7
    assert len(polynomial.terms) == 2
    assert Monomial.variable("x") ** 0 == Monomial()


def test_mimc_execution_satisfies_lowered_equations():
    cipher = MiMCPermutation(17, 3, (1, 2, 4))
    evaluation = ScalarEvaluator().evaluate(cipher, {"state": (5,)})
    system = PrimeFieldPolynomialModel(cipher).polynomial_system()

    assert len(system.variables) == 10
    assert len(system.equations) == 9
    assert system.maximum_degree == 3
    assert system.evaluate(_assignment_from_evaluation(evaluation)) == (0,) * 9


def test_poseidon_execution_satisfies_lowered_equations():
    cipher = PoseidonPermutation(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1, 2), (3, 4), (5, 6)),
        linear_layer=((1, 1), (1, 2)),
    )
    evaluation = ScalarEvaluator().evaluate(cipher, {"state": (2, 7)})
    system = PrimeFieldPolynomialModel(cipher).polynomial_system()

    assert system.maximum_degree == 3
    assert system.evaluate(_assignment_from_evaluation(evaluation)) == (0,) * len(system.equations)
    assert set(system.provenance) == {component.component_id for component in cipher.components}


def test_prime_field_model_rejects_bit_graph():
    cipher = Cipher("bits", {"state": ValueType(Bit(), (2,))})

    with pytest.raises(ValueError, match="homogeneous prime field"):
        PrimeFieldPolynomialModel(cipher)
