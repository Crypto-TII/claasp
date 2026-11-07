"""uLBC block-cipher vectors from the design paper, Appendix A."""

import pytest

from claasp.primitives import ULBC


@pytest.mark.parametrize(
    "bits,p,k,c",
    [
        (128, 0, 0, 0xE6B6B249C25994A425C480B852F4899A),
        (
            128,
            0x2D33F9E14C935DC3150E07EF14909C24,
            0x2F5A39F65EF0D47B4C2AE6B521FB0A08,
            0x5384BF47150A1F05059C1E704894CA21,
        ),
        (256, 0, 0, 0xFB0BE7250CFD59A9D2712FB1899FF396),
        (
            256,
            0x2D6430850CAD830B53764DAD7BE5C3A9,
            0x2990CBCB613391BE00A582CD722E610F42E65A592135AB5F4A85FB01222224E0,
            0xB6CFA6A590DBA5EAA5A7004E5A8339F4,
        ),
    ],
)
def test_ulbc_published_vectors(bits, p, k, c):
    assert ULBC(key_bit_size=bits).evaluate(plaintext=p, key=k) == c


@pytest.mark.parametrize(
    "kwargs", [{"key_bit_size": 192}, {"number_of_rounds": 0}, {"number_of_rounds": 19}]
)
def test_invalid_parameters(kwargs):
    with pytest.raises(ValueError):
        ULBC(**kwargs)


def test_specification_instances_are_separate_from_round_reductions():
    primitive = ULBC(number_of_rounds=2)
    assert len(primitive.graph.rounds) == 2
    assert {r.values["key_bit_size"] for r in primitive.instances} == {128, 256}
