"""SAND tests against the designers' published vectors and reference code.

The two full-round plaintext, key and ciphertext triples below are copied from
Appendix A of Chen et al., *SAND: an AND-RX Feistel lightweight block cipher
supporting S-box-based security evaluations*, Designs, Codes and Cryptography
90, 155--198 (2022), https://doi.org/10.1007/s10623-021-00970-9
(open version: https://eprint.iacr.org/2021/1560). The independent scalar oracle
follows the bitslice reference code in Appendix B of that open version; the
CLAASP graph instead wires bit planes and permutation tables explicitly.
"""

import random

import pytest

from claasp.ciphers.block_ciphers.sand_block_cipher import SandBlockCipher


def scalar_keys(master, width, rounds):
    mask = (1 << width) - 1
    keys = [(master >> (j * width)) & mask for j in range(128 // width)]
    words = len(keys)
    for r in range(words, rounds):
        transformed = keys[-1]
        for _ in range(3):
            transformed = ((transformed >> 4) | (transformed << (width - 4))) & mask
            nibble = (transformed >> (width - 8)) & 15
            transformed ^= (((nibble << 1) | (nibble >> 3)) & 15) << (width - 4)
            transformed ^= ((nibble << 3) & 15) << (width - 8)
        keys.append(transformed ^ keys[r - words] ^ (r - words + 1))
    return keys[:rounds]


def scalar_round_function(x, width):
    mask = (1 << width) - 1
    def repeat(nibble):
        return sum(nibble << i for i in range(0, width, 4))
    a = x ^ ((x >> 3) & (x >> 2) & repeat(1))
    a ^= (a << 3) & (a << 2) & repeat(8)
    b = ((x << 4) | (x >> (width - 4))) & mask
    b ^= (b >> 1) & (b << 1) & repeat(4)
    b ^= (b << 1) & (b >> 1) & repeat(2)
    combined = a ^ b
    chunk = width // 8
    low = sum(((1 << chunk) - 1) << i for i in range(0, width, 2 * chunk))
    def rotate(value, amount):
        return ((value << amount) | (value >> (width - amount))) & mask
    return rotate(combined & low, width - chunk) | rotate(
        combined & (mask ^ low), 3 * chunk
    )


def scalar_apply(value, keys, width):
    x, y = value >> width, value & ((1 << width) - 1)
    for key in keys:
        x, y = y ^ scalar_round_function(x, width) ^ key, x
    return (y << width) | x


@pytest.mark.parametrize(
    "block,plain,key,expected",
    [
        (
            64,
            0x0F1F2F3F4F5F6F7F,
            0x0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFF,
            0x4DE90F3B2B5E706B,
        ),
        (
            128,
            0xFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0F,
            0x1F1E1D1C1B1A19181716151413121110,
            0xF1FBE865BECE10F82A34C6C99D6A7303,
        ),
    ],
)
def test_sand_published_full_round_vectors(block, plain, key, expected):
    cipher = SandBlockCipher(block_bit_size=block)
    keys = scalar_keys(key, block // 2, cipher.number_of_rounds)
    assert scalar_apply(plain, keys, block // 2) == expected
    assert cipher.evaluate([plain, key]) == expected
    assert cipher.cipher_inverse().evaluate([expected, key]) == plain
    assert scalar_apply(expected, list(reversed(keys)), block // 2) == plain


@pytest.mark.parametrize("block", [64, 128])
@pytest.mark.parametrize("rounds", [1, 2, 5, 13])
def test_sand_reduced_rounds_match_scalar_and_inverse(block, rounds):
    cipher = SandBlockCipher(block_bit_size=block, number_of_rounds=rounds)
    rng = random.Random(20261209 + block + rounds)
    for _ in range(4):
        plain, key = rng.getrandbits(block), rng.getrandbits(128)
        keys = scalar_keys(key, block // 2, rounds)
        expected = scalar_apply(plain, keys, block // 2)
        assert cipher.evaluate([plain, key]) == expected
        assert scalar_apply(expected, list(reversed(keys)), block // 2) == plain


@pytest.mark.parametrize(
    "parameters",
    [
        {"block_bit_size": 32},
        {"block_bit_size": 64.0},
        {"key_bit_size": 64},
        {"number_of_rounds": 0},
        {"number_of_rounds": True},
        {"number_of_rounds": 1.5},
        {"number_of_rounds": 49},
        {"block_bit_size": 128, "number_of_rounds": 55},
    ],
)
def test_sand_rejects_unsupported_parameters(parameters):
    with pytest.raises(ValueError, match="SAND"):
        SandBlockCipher(**parameters)


@pytest.mark.parametrize("block", [64, 128])
def test_sand_exact_boomerang_graph_uses_actual_expanded_key(block):
    from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
        MznHadipourBoomerangModel,
    )
    from claasp.cipher_modules.models.utils import (
        integer_to_bit_list,
        set_fixed_variables,
    )

    cipher = SandBlockCipher(block_bit_size=block, number_of_rounds=5)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=3,
            bottom_part_number_of_rounds=1,
        ),
        middle_model="exact",
    )
    def fix(name, value, size):
        return set_fixed_variables(
            name, "equal", list(range(size)), integer_to_bit_list(value, size, "big")
        )
    # Returning-pair calibration only: this is not a cryptanalytic distinguisher.
    inputs = [2, 3, 3, 2]
    key = 0x0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFF
    fixed = [fix(f"quartet_{j}_plaintext", x, block) for j, x in enumerate(inputs)]
    fixed.append(fix("quartet_0_key", key, 128))
    result = model.find_one_boomerang_trail(
        fixed_values=fixed, solver_name="cp-sat", timeout_in_seconds=20, processes=2
    )
    assert result["status"] == "SATISFIABLE"
    output = cipher.all_components_ids()[-1]
    for j, x in enumerate(inputs):
        value = int(result["quartet_values"][f"quartet_{j}_{output}"]["value"], 16)
        assert value == scalar_apply(x, scalar_keys(key, block // 2, 5), block // 2)
