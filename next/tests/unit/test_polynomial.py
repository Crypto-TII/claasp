import pytest

from claasp_next import Bit, PrimeField, Primitive, ScalarEvaluator, ValueType
from claasp_next.primitives import MiMC, Poseidon
from claasp_next.representations.constraints.polynomial import (
    Monomial,
    Polynomial,
    PowerLoweringPolicy,
    PrimeFieldPolynomialModel,
)


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
    primitive = MiMC(17, 3, (1, 2, 4))
    evaluation = ScalarEvaluator().evaluate(primitive, {"state": (5,)})
    system = PrimeFieldPolynomialModel(primitive).polynomial_system()

    assert len(system.variables) == 10
    assert len(system.equations) == 9
    assert system.maximum_degree == 3
    assert system.evaluate(_assignment_from_evaluation(evaluation)) == (0,) * 9


def test_poseidon_execution_satisfies_lowered_equations():
    primitive = Poseidon(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1, 2), (3, 4), (5, 6)),
        linear_layer=((1, 1), (1, 2)),
    )
    evaluation = ScalarEvaluator().evaluate(primitive, {"state": (2, 7)})
    system = PrimeFieldPolynomialModel(primitive).polynomial_system()

    assert system.maximum_degree == 3
    assert system.evaluate(_assignment_from_evaluation(evaluation)) == (0,) * len(system.equations)
    assert set(system.provenance) == {component.component_id for component in primitive.components}


def test_prime_field_model_rejects_bit_graph():
    primitive = Primitive("bits", {"state": ValueType(Bit(), (2,))})

    with pytest.raises(ValueError, match="homogeneous prime field"):
        PrimeFieldPolynomialModel(primitive)


def test_binary_chain_lowers_degree_and_witness_satisfies_auxiliary_equations():
    primitive = MiMC(17, 5, (1,))
    evaluation = ScalarEvaluator().evaluate(primitive, {"state": (3,)})
    direct = PrimeFieldPolynomialModel(primitive).polynomial_system()
    model = PrimeFieldPolynomialModel(primitive, PowerLoweringPolicy.BINARY_CHAIN)
    chained = model.polynomial_system()

    assert direct.maximum_degree == 5
    assert chained.maximum_degree == 2
    assert len(chained.variables) == len(direct.variables) + 2
    assert chained.evaluate(model.witness(evaluation)) == (0,) * len(chained.equations)
    assert chained.provenance[-1] == "power_0_2:unit=0:power=5"


def test_polynomial_statistics_report_degrees_terms_and_incidence():
    system = PrimeFieldPolynomialModel(
        MiMC(17, 5, (1,)), power_lowering="binary_chain"
    ).polynomial_system()
    statistics = system.statistics

    assert statistics.variable_count == 6
    assert statistics.equation_count == 5
    assert statistics.term_count == 11
    assert statistics.degree_histogram == ((1, 2), (2, 3))
    assert dict(statistics.variable_incidence)["power_0_2_0"] == 1


def test_power_lowering_policy_is_validated():
    with pytest.raises(ValueError, match="direct, binary_chain"):
        PrimeFieldPolynomialModel(MiMC(17, 3, (1,)), "expanded")
