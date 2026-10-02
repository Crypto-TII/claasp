"""Independent pseudocode and bounded evaluation for the legacy Speck8/16 toy."""

import pytest

from claasp.primitives import Speck, ToySpeck


def _reference(plaintext, key, rounds):
    left, right = plaintext >> 4, plaintext & 15
    keys = [key & 15]
    schedule = [(key >> shift) & 15 for shift in (4, 8, 12)]
    for r in range(rounds - 1):
        word = ((schedule[r] + keys[r]) & 15) ^ r
        schedule.append(word)
        keys.append(((keys[r] << 3) | (keys[r] >> 1)) & 15 ^ word)
    for r in range(rounds):
        left = ((left + right) & 15) ^ keys[r]
        right = (((right << 3) | (right >> 1)) & 15) ^ left
    return (left << 4) | right


@pytest.mark.parametrize("rounds", [1, 2, 3, 4])
def test_toy_speck_matches_independent_pseudocode_and_is_bijective(rounds):
    primitive = ToySpeck(rounds)
    for key in (0, 0x1234, 0xFFFF):
        outputs = [primitive.evaluate(value, key) for value in range(256)]
        assert outputs == [_reference(value, key, rounds) for value in range(256)]
        assert len(set(outputs)) == 256
    assert primitive.family_name == "toy_speck"


def test_toy_is_not_an_official_speck_configuration():
    with pytest.raises(ValueError):
        Speck(block_bit_size=8, key_bit_size=16)
    with pytest.raises(ValueError):
        ToySpeck(True)
    assert ToySpeck().evaluate(0x53, 0x1234) == 0xE2
