from claasp.ciphers.block_ciphers.blowfish_block_cipher import BlowfishBlockCipher
"""
The test vectors are taken from the Internet Draft draft-schneier-blowfish-00.txt 'Description of the Blowfish Cipher'.
Link: https://datatracker.ietf.org/doc/html/draft-schneier-blowfish-00
"""

def test_blowfish_block_cipher():
    test_vectors = [
        (
            0x0000000000000000,
            0x0000000000000000,
            0x4EF997456198DD78,
        ),
        (
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x51866FD5B85ECB8A,
        ),
        (
            0x3000000000000000,
            0x1000000000000001,
            0x7D856F9A613063F2,
        ),
        (
            0x1111111111111111,
            0x1111111111111111,
            0x2466DD878B963C9D,
        ),
        (
            0x0123456789ABCDEF,
            0x1111111111111111,
            0x61F9C3802281B096,
        ),
        (
            0x1111111111111111,
            0x0123456789ABCDEF,
            0x7D0CC630AFDA1EC7,
        ),
    ]

    for key, plaintext, expected_ciphertext in test_vectors:
        blowfish = BlowfishBlockCipher(
            key=key,
            key_bit_size=64,
        )

        assert blowfish.type == "block_cipher"
        assert blowfish.family_name == "blowfish"
        assert blowfish.number_of_rounds == 16
        assert blowfish.output_bit_size == 64
        assert blowfish.inputs_bit_size == [64]

        assert blowfish.evaluate([plaintext]) == expected_ciphertext


def test_blowfish_variable_key_size():
    plaintext = 0xFEDCBA9876543210

    test_vectors = [
        (
            0xF0E1D2C3,
            32,
            0xBE1E639408640F05,
        ),
        (
            0xF0E1D2C3B4A59687,
            64,
            0xE87A244E2CC85E82,
        ),
        (
            0xF0E1D2C3B4A5968778695A4B3C2D1E0F,
            128,
            0x93142887EE3BE15C,
        ),
    ]

    for key, key_bit_size, expected_ciphertext in test_vectors:
        blowfish = BlowfishBlockCipher(
            key=key,
            key_bit_size=key_bit_size,
        )

        assert blowfish.evaluate([plaintext]) == expected_ciphertext


def test_blowfish_evaluate_using_c():
    blowfish = BlowfishBlockCipher(
        key=0x0000000000000000,
        key_bit_size=64,
    )

    plaintext = 0x0000000000000000
    expected_ciphertext = 0x4EF997456198DD78

    assert blowfish.evaluate_using_c([plaintext]) == expected_ciphertext


def test_blowfish_invalid_key_size():
    try:
        BlowfishBlockCipher(
            key=0,
            key_bit_size=24,
        )
        assert False, "Expected ValueError for invalid key_bit_size"
    except ValueError as exception:
        assert "between 32 and 448 bits" in str(exception)

    try:
        BlowfishBlockCipher(
            key=0,
            key_bit_size=456,
        )
        assert False, "Expected ValueError for invalid key_bit_size"
    except ValueError as exception:
        assert "between 32 and 448 bits" in str(exception)
