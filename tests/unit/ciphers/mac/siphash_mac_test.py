import pytest

from claasp.ciphers.mac.siphash_mac import SiphashMAC


def _int_from_bytes_big_endian(byte_values):
    return int.from_bytes(bytes(byte_values), byteorder='big')


def _siphash64_expected_from_le_bytes(byte_values):
    return int.from_bytes(bytes(byte_values), byteorder='little')


def _siphash128_expected_from_le_bytes(byte_values):
    first_word = int.from_bytes(bytes(byte_values[:8]), byteorder='little')
    second_word = int.from_bytes(bytes(byte_values[8:]), byteorder='little')

    return (first_word << 64) | second_word


def test_siphash_mac_parameterization():
    siphash = SiphashMAC(message_byte_size=16, compression_rounds=1, finalization_rounds=3, output_bit_size=64)
    assert siphash.type == 'hash_function'
    assert siphash.family_name == 'siphash'

    siphash_128 = SiphashMAC(
        message_byte_size=16,
        compression_rounds=2,
        finalization_rounds=4,
        output_bit_size=128,
    )
    assert siphash_128.output_bit_size == 128


def test_siphash24_vector_from_paper_page_19_and_vectors_h():
    # Reference: https://cr.yp.to/siphash/siphash-20120918.pdf (page 19 test vector)
    # Reference: https://github.com/veorq/SipHash/blob/master/vectors.h (vectors_sip64[15])
    key_bytes = list(range(16))
    message_bytes = list(range(15))
    expected_le_bytes = [0xE5, 0x45, 0xBE, 0x49, 0x61, 0xCA, 0x29, 0xA1]

    siphash = SiphashMAC(message_byte_size=15, compression_rounds=2, finalization_rounds=4, output_bit_size=64)
    key = _int_from_bytes_big_endian(key_bytes)
    message = _int_from_bytes_big_endian(message_bytes)
    expected = _siphash64_expected_from_le_bytes(expected_le_bytes)

    assert siphash.evaluate([key, message]) == expected
    assert siphash.evaluate_vectorized([key, message], evaluate_api=True) == expected


@pytest.mark.parametrize(
    'message_size,expected_le_bytes',
    [
        (0, [0x31, 0x0E, 0x0E, 0xDD, 0x47, 0xDB, 0x6F, 0x72]),
        (63, [0x72, 0x45, 0x06, 0xEB, 0x4C, 0x32, 0x8A, 0x95]),
    ],
)
def test_siphash24_vectors_h_selected(message_size, expected_le_bytes):
    # Reference: https://github.com/veorq/SipHash/blob/master/vectors.h (vectors_sip64)
    key = _int_from_bytes_big_endian(range(16))
    message = _int_from_bytes_big_endian(range(message_size)) if message_size > 0 else 0
    expected = _siphash64_expected_from_le_bytes(expected_le_bytes)

    siphash = SiphashMAC(message_byte_size=message_size, compression_rounds=2, finalization_rounds=4)
    assert siphash.evaluate([key, message]) == expected


def test_siphash128_vectors_h_selected():
    # Reference: https://github.com/veorq/SipHash/blob/master/vectors.h (vectors_sip128[15])
    key = _int_from_bytes_big_endian(range(16))
    message = _int_from_bytes_big_endian(range(15))
    expected_le_bytes = [
        0x54,
        0x93,
        0xE9,
        0x99,
        0x33,
        0xB0,
        0xA8,
        0x11,
        0x7E,
        0x08,
        0xEC,
        0x0F,
        0x97,
        0xCF,
        0xC3,
        0xD9,
    ]
    expected = _siphash128_expected_from_le_bytes(expected_le_bytes)

    siphash_128 = SiphashMAC(message_byte_size=15, compression_rounds=2, finalization_rounds=4, output_bit_size=128)
    assert siphash_128.evaluate([key, message]) == expected