from claasp.ciphers.permutations.grain_core_permutation import GrainCorePermutation


def _int_to_bits_msb_first(value, n):
    return [(value >> (n - 1 - i)) & 1 for i in range(n)]


def _bits_to_int_msb_first(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _bits_to_bytes_lsb_first(bits):
    assert len(bits) % 8 == 0
    output = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        output[i // 8] |= bit << (i % 8)
    return bytes(output)


def _grain_v1_keystream_mode_clock(s, b, number_of_bits):
    """
    Plain-Python re-implementation (independent of the claasp component) of Grain v1's
    KEYSTREAM GENERATION mode: unlike the initialization core (which XORs the output bit z_i
    back into both registers), keystream generation just clocks the registers normally and
    releases z_i as output.

    ``s`` and ``b`` are 80-element bit lists (index 0 = s_0 / b_0), as produced right after the
    160 initialization clocks. Returns a list of ``number_of_bits`` keystream bits z_0, z_1, ...
    """
    s = list(s)
    b = list(b)
    keystream_bits = []

    for _ in range(number_of_bits):
        x0, x1, x2, x3, x4 = s[3], s[25], s[46], s[64], b[63]
        h = (
            x1 ^ x4
            ^ (x0 & x3) ^ (x2 & x3) ^ (x3 & x4)
            ^ (x0 & x1 & x2) ^ (x0 & x2 & x3) ^ (x0 & x2 & x4) ^ (x1 & x2 & x4) ^ (x2 & x3 & x4)
        )
        z = h ^ b[1] ^ b[2] ^ b[4] ^ b[10] ^ b[31] ^ b[43] ^ b[56]
        keystream_bits.append(z)

        f = s[0] ^ s[13] ^ s[23] ^ s[38] ^ s[51] ^ s[62]

        g_linear = b[0] ^ b[9] ^ b[14] ^ b[21] ^ b[28] ^ b[33] ^ b[37] ^ b[45] ^ b[52] ^ b[60] ^ b[62]
        g_products = (
            (b[63] & b[60]) ^ (b[37] & b[33]) ^ (b[15] & b[9])
            ^ (b[60] & b[52] & b[45]) ^ (b[33] & b[28] & b[21])
            ^ (b[63] & b[45] & b[28] & b[9]) ^ (b[60] & b[52] & b[37] & b[33])
            ^ (b[63] & b[60] & b[21] & b[15]) ^ (b[63] & b[60] & b[52] & b[45] & b[37])
            ^ (b[33] & b[28] & b[21] & b[15] & b[9])
            ^ (b[52] & b[45] & b[37] & b[33] & b[28] & b[21])
        )
        g = g_linear ^ g_products

        new_s = f
        new_b = s[0] ^ g

        s = s[1:] + [new_s]
        b = b[1:] + [new_b]

    return keystream_bits


def test_grain_core_permutation_attributes():
    grain_core = GrainCorePermutation()
    assert grain_core.family_name == "grain_core"
    assert grain_core.type == "permutation"
    assert grain_core.number_of_rounds == 160

    grain_core_4 = GrainCorePermutation(number_of_rounds=4)
    assert grain_core_4.number_of_rounds == 4


def test_grain_core_permutation_official_test_vector_a():
    # Official Grain v1 KAT: key = 0, IV = 0.
    input_state_int = 0x0000000000000000FFFF00000000000000000000
    expected_output_int = 0x4EB431BCC5344EFB12DA6D7B0599918A2F079726

    grain_core = GrainCorePermutation(number_of_rounds=160)
    output_int = grain_core.evaluate([input_state_int])

    assert output_int == expected_output_int

    lfsr_int = output_int >> 80
    nfsr_int = output_int & ((1 << 80) - 1)
    s = _int_to_bits_msb_first(lfsr_int, 80)
    b = _int_to_bits_msb_first(nfsr_int, 80)

    keystream_bits = _grain_v1_keystream_mode_clock(s, b, 80)
    keystream_bytes = _bits_to_bytes_lsb_first(keystream_bits)

    assert keystream_bytes.hex() == "dee931cf1662a72f77d0"


def test_grain_core_permutation_official_test_vector_b():
    # Official Grain v1 KAT: key = 0123456789abcdef1234, IV = 0123456789abcdef.
    input_state_int = 0x80C4A2E691D5B3F7FFFF80C4A2E691D5B3F7482C
    expected_output_int = 0x3B56DF4AB9E8FAD94FA73A310D1DCB0D15E35AF7

    grain_core = GrainCorePermutation(number_of_rounds=160)
    output_int = grain_core.evaluate([input_state_int])

    assert output_int == expected_output_int

    lfsr_int = output_int >> 80
    nfsr_int = output_int & ((1 << 80) - 1)
    s = _int_to_bits_msb_first(lfsr_int, 80)
    b = _int_to_bits_msb_first(nfsr_int, 80)

    keystream_bits = _grain_v1_keystream_mode_clock(s, b, 80)
    keystream_bytes = _bits_to_bytes_lsb_first(keystream_bits)

    assert keystream_bytes.hex() == "7f362bd3f7abae203664"
