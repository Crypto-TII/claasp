"""uLBC-384t Appendix A vectors and bit-exact key/tweak splitting."""

import pytest

from claasp.primitives import ULBCTweakable


@pytest.mark.parametrize(
    "p,tk,c",
    [
        (0, 0, 0x64ADEB0232294D9C1E268365764E674A),
        (
            0x2D7D941A0F864E4B3A7E25E32FE97815,
            0x08CAC34637DA2D2C54CBC0590CC13E8D62F1A18565A355824642FDEF582D79F211A12C186C55E4B27B1999AE4DB8ADA5,
            0x6BFE00BA63397825379E397EFA11D15A,
        ),
    ],
)
@pytest.mark.parametrize("key_bits", [128, 129, 255, 256, 383, 384])
def test_ulbc_384t_published_vectors_and_bit_exact_key_tweak_splits(p, tk, c, key_bits):
    tweak_bits = 384 - key_bits
    inputs = {"plaintext": p, "key": tk >> tweak_bits}
    if tweak_bits:
        inputs["tweak"] = tk & ((1 << tweak_bits) - 1)
    assert ULBCTweakable(key_bit_size=key_bits).evaluate(inputs) == c


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_bit_size": 127},
        {"key_bit_size": 385},
        {"number_of_rounds": 31},
        {"number_of_rounds": False},
    ],
)
def test_invalid_parameters(kwargs):
    with pytest.raises(ValueError):
        ULBCTweakable(**kwargs)
