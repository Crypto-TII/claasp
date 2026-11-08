"""Circle-difference verification on binary catalogue graphs.

Pair construction and output differences use an independent packed-bit
formula for the published four-bit operation.
"""

from fractions import Fraction
from random import Random

import pytest

from claasp.primitives import (
    AES,
    ULBC,
    Craft,
    Noekeon,
    Present,
    Pride,
    Simon,
    Speck,
    ToyAES,
    ToySpeck,
    ULBCTweakable,
)
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace

OPERATION = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))


def _circle(x, y, width):
    correction = 0
    for shift in range(0, width, 4):
        left, right = x >> shift, y >> shift
        bit = (((left >> 3) & 1) & ((right >> 2) & 1)) ^ (((left >> 2) & 1) & ((right >> 3) & 1))
        correction |= bit << shift
    return x ^ y ^ correction


@pytest.mark.parametrize(
    "primitive",
    [
        AES(number_of_rounds=2),
        Present(number_of_rounds=2),
        Craft(number_of_rounds=2),
        Speck(number_of_rounds=2),
        Simon(number_of_rounds=2),
        Noekeon(number_of_rounds=2),
        Pride(number_of_rounds=2),
        ULBC(number_of_rounds=2),
        ULBCTweakable(number_of_rounds=2),
    ],
    ids=[
        "AES-2",
        "PRESENT-2",
        "CRAFT-2",
        "Speck32-2",
        "Simon32-2",
        "NOEKEON-2",
        "PRIDE-2",
        "uLBC-2",
        "uLBC-384t-2",
    ],
)
def test_standard_primitive_circle_sampling_matches_independent_pair_oracle(primitive):
    analysis = primitive.analysis.circle_differential(bibrace=OPERATION)
    width = analysis.input_basis.width
    fixed = {name: 0 for name in primitive.graph.input_arrays if name != "plaintext"}
    alpha = 7
    # Define the endpoint using the fixed pilot pair (0, alpha), before
    # drawing validation samples. This is not a search for a strong attack.
    beta = _circle(
        primitive.evaluate({**fixed, "plaintext": 0}),
        primitive.evaluate({**fixed, "plaintext": alpha}),
        width,
    )
    rng = Random(17)
    expected = 0
    for _ in range(64):
        x = rng.getrandbits(width)
        y = _circle(x, alpha, width)
        left = primitive.evaluate({**fixed, "plaintext": x})
        right = primitive.evaluate({**fixed, "plaintext": y})
        expected += _circle(left, right, width) == beta
    result = analysis.estimate_probability(alpha, beta, fixed_inputs=fixed, samples=64, seed=17)
    assert result.hits == expected
    assert result.probability == Fraction(expected, 64)
    assert result.lower <= float(result.probability) <= result.upper
    assert not result.complete and result.seed == 17
    assert result.input_basis.width == result.output_basis.width == width


@pytest.mark.parametrize(
    "primitive",
    [ToySpeck(number_of_rounds=2), ToyAES(number_of_rounds=2, word_size=2, state_size=2)],
    ids=["ToySpeck8-2", "ToyAES8-2"],
)
def test_small_primitive_exact_probability_and_concrete_search_match_complete_pair_oracle(
    primitive,
):
    analysis = primitive.analysis.circle_differential(bibrace=OPERATION)
    width = analysis.input_basis.width
    assert width == 8
    fixed = {"key": 0}
    histogram: dict[int, int] = {}
    for x in range(256):
        y = _circle(x, 7, width)
        beta = _circle(
            primitive.evaluate({**fixed, "plaintext": x}),
            primitive.evaluate({**fixed, "plaintext": y}),
            width,
        )
        histogram[beta] = histogram.get(beta, 0) + 1
    beta = max(sorted(histogram), key=histogram.__getitem__)
    exact = analysis.probability(7, beta, fixed_inputs=fixed)
    assert exact.probability == Fraction(histogram[beta], 256) and exact.complete
    trail = primitive.analysis.find_lowest_weight_circle_differential_trail(
        bibrace=OPERATION,
        input_difference=7,
        output_difference=beta,
        fixed_inputs=fixed,
    )
    checked = analysis.trail_probability(trail.differences, fixed_inputs=fixed)
    assert trail.probability == checked.probability
    assert 0 < trail.probability <= exact.probability
    assert trail.witness is not None and checked.evidence.complete
