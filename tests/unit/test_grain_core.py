import pytest

from claasp.primitives import GrainCore


def _int_to_bits_msb_first(value, size):
    return [(value >> (size - 1 - index)) & 1 for index in range(size)]


def _bits_to_bytes_lsb_first(bits):
    output = bytearray(len(bits) // 8)
    for index, bit in enumerate(bits):
        output[index // 8] |= bit << (index % 8)
    return bytes(output)


def _keystream_after_initialization(lfsr, nfsr, number_of_bits):
    """Independently clock Grain v1 in keystream-generation mode."""
    lfsr = list(lfsr)
    nfsr = list(nfsr)
    output = []
    for _ in range(number_of_bits):
        x0, x1, x2, x3, x4 = lfsr[3], lfsr[25], lfsr[46], lfsr[64], nfsr[63]
        h = (
            x1
            ^ x4
            ^ (x0 & x3)
            ^ (x2 & x3)
            ^ (x3 & x4)
            ^ (x0 & x1 & x2)
            ^ (x0 & x2 & x3)
            ^ (x0 & x2 & x4)
            ^ (x1 & x2 & x4)
            ^ (x2 & x3 & x4)
        )
        output.append(h ^ nfsr[1] ^ nfsr[2] ^ nfsr[4] ^ nfsr[10] ^ nfsr[31] ^ nfsr[43] ^ nfsr[56])
        lfsr_feedback = lfsr[0] ^ lfsr[13] ^ lfsr[23] ^ lfsr[38] ^ lfsr[51] ^ lfsr[62]
        nfsr_feedback = (
            nfsr[0]
            ^ nfsr[9]
            ^ nfsr[14]
            ^ nfsr[21]
            ^ nfsr[28]
            ^ nfsr[33]
            ^ nfsr[37]
            ^ nfsr[45]
            ^ nfsr[52]
            ^ nfsr[60]
            ^ nfsr[62]
            ^ (nfsr[63] & nfsr[60])
            ^ (nfsr[37] & nfsr[33])
            ^ (nfsr[15] & nfsr[9])
            ^ (nfsr[60] & nfsr[52] & nfsr[45])
            ^ (nfsr[33] & nfsr[28] & nfsr[21])
            ^ (nfsr[63] & nfsr[45] & nfsr[28] & nfsr[9])
            ^ (nfsr[60] & nfsr[52] & nfsr[37] & nfsr[33])
            ^ (nfsr[63] & nfsr[60] & nfsr[21] & nfsr[15])
            ^ (nfsr[63] & nfsr[60] & nfsr[52] & nfsr[45] & nfsr[37])
            ^ (nfsr[33] & nfsr[28] & nfsr[21] & nfsr[15] & nfsr[9])
            ^ (nfsr[52] & nfsr[45] & nfsr[37] & nfsr[33] & nfsr[28] & nfsr[21])
        )
        new_nfsr_bit = lfsr[0] ^ nfsr_feedback
        lfsr = lfsr[1:] + [lfsr_feedback]
        nfsr = nfsr[1:] + [new_nfsr_bit]
    return output


@pytest.mark.parametrize(
    ("initial_state", "initialized_state", "keystream"),
    (
        (
            0x0000000000000000FFFF00000000000000000000,
            0x4EB431BCC5344EFB12DA6D7B0599918A2F079726,
            "dee931cf1662a72f77d0",
        ),
        (
            0x80C4A2E691D5B3F7FFFF80C4A2E691D5B3F7482C,
            0x3B56DF4AB9E8FAD94FA73A310D1DCB0D15E35AF7,
            "7f362bd3f7abae203664",
        ),
    ),
)
def test_grain_v1_official_vectors(initial_state, initialized_state, keystream):
    output = GrainCore().evaluate(initial_state)
    assert output == initialized_state

    lfsr = _int_to_bits_msb_first(output >> 80, 80)
    nfsr = _int_to_bits_msb_first(output & ((1 << 80) - 1), 80)
    bits = _keystream_after_initialization(lfsr, nfsr, 80)
    assert _bits_to_bytes_lsb_first(bits).hex() == keystream


@pytest.mark.parametrize("rounds", (0, -1, 1.5, True, "160"))
def test_grain_core_rejects_invalid_round_counts(rounds):
    with pytest.raises(ValueError, match="positive integer"):
        GrainCore(number_of_rounds=rounds)
