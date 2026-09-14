import pytest

from claasp_next.primitives import Simon
from claasp_next.representations.execution import BatchEvaluator, TransposedBatchEvaluator


@pytest.mark.parametrize(("block_size", "key_size", "plaintext", "key", "ciphertext"), (
    (32, 64, 0x65656877, 0x1918111009080100, 0xC69BE9BB),
    (48, 72, 0x6120676E696C, 0x1211100A0908020100, 0xDAE5AC292CAC),
    (48, 96, 0x72696320646E, 0x1A19181211100A0908020100, 0x6E06A5ACF156),
    (128, 256, 0x74206E69206D6F6F6D69732061207369,
     0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100,
     0x8D2B5579AFC8A3A03BF72A87EFE7B868),
))
def test_simon_preserves_legacy_and_official_vectors(block_size, key_size, plaintext, key, ciphertext):
    primitive = Simon(block_size, key_size)

    assert primitive.evaluate(plaintext, key) == ciphertext
    width = block_size // 2
    mask = (1 << width) - 1
    inputs = {
        "plaintext": (((plaintext >> width) & mask, plaintext & mask),),
        "key": (tuple(
            (key >> shift) & mask for shift in range(key_size - width, -1, -width)
        ),),
    }
    expected = (((ciphertext >> width) & mask, ciphertext & mask),)
    assert BatchEvaluator().evaluate(primitive, inputs).outputs == expected
    assert TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == expected


def test_simon_rejects_invalid_parameters():
    with pytest.raises(ValueError, match="unsupported"):
        Simon(32, 128)
    with pytest.raises(ValueError, match="between 1 and 32"):
        Simon(number_of_rounds=33)
