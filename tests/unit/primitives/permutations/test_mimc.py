from claasp.primitives import MiMC
from claasp.representations.execution import ScalarEvaluator


def test_toy_mimc_matches_direct_computation():
    modulus = 17
    exponent = 3
    constants = (1, 2, 4)
    primitive = MiMC(modulus, exponent, constants)

    expected = 5
    for constant in constants:
        expected = pow(expected + constant, exponent, modulus)

    result = ScalarEvaluator().evaluate(primitive, {"state": (5,)})

    assert result.output == (expected,)
    assert len(primitive.graph.rounds) == len(constants)
    assert len(primitive.graph.components) == 3 * len(constants)
