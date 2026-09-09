from claasp_next.ciphers import MiMCPermutation
from claasp_next.evaluators import ScalarEvaluator


def test_toy_mimc_matches_direct_computation():
    modulus = 17
    exponent = 3
    constants = (1, 2, 4)
    cipher = MiMCPermutation(modulus, exponent, constants)

    expected = 5
    for constant in constants:
        expected = pow(expected + constant, exponent, modulus)

    result = ScalarEvaluator().evaluate(cipher, {"state": (5,)})

    assert result.output == (expected,)
    assert len(cipher.rounds) == len(constants)
    assert len(cipher.components) == 3 * len(constants)
