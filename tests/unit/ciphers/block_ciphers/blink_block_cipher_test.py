import pytest

from claasp.ciphers.block_ciphers.blink_block_cipher import BlinkBlockCipher


KEY_448 = int(
    "d6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21"
    "6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1",
    16,
)

KEY_1024 = int(
    "d6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21"
    "6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f"
    "2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b6"
    "21b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4",
    16,
)

KEY_1280 = int(
    "d6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21"
    "6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f"
    "2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b6"
    "21b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4"
    "28962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d",
    16,
)

PLAINTEXT = 0x0
TWEAK_64 = 0x0123456789ABCDEF
TWEAK_128 = 0x0123456789ABCDEF0123456789ABCDEF
TWEAK_256 = int(
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef",
    16,
)


def test_blink_64a():
    blink = BlinkBlockCipher(
        block_bit_size=64,
        tweak_bit_size=64,
        key_bit_size=448,
        a=2,
        b=3,
    )

    assert blink.type == "block_cipher"
    assert blink.family_name == "blink"
    assert blink.evaluate(
        [KEY_448, PLAINTEXT, TWEAK_64]
    ) == 0xA4A0D10502BE846E


def test_blink_64b():
    blink = BlinkBlockCipher(
        block_bit_size=64,
        tweak_bit_size=128,
        key_bit_size=448,
        a=2,
        b=3,
    )

    assert blink.evaluate(
        [KEY_448, PLAINTEXT, TWEAK_128]
    ) == 0x743E142F17CAAAE1


def test_blink_128a():
    blink = BlinkBlockCipher(
        block_bit_size=128,
        tweak_bit_size=128,
        key_bit_size=1024,
        a=3,
        b=3,
    )

    expected = 0x713FC1546D924BF9CB4E96812EEFF9AC

    assert blink.evaluate(
        [KEY_1024, PLAINTEXT, TWEAK_128]
    ) == expected

    assert blink.evaluate_vectorized(
        [KEY_1024, PLAINTEXT, TWEAK_128],
        evaluate_api=True,
    ) == expected


def test_blink_128b():
    blink = BlinkBlockCipher(
        block_bit_size=128,
        tweak_bit_size=256,
        key_bit_size=1024,
        a=3,
        b=3,
    )

    assert blink.evaluate(
        [KEY_1024, PLAINTEXT, TWEAK_256]
    ) == 0xC5C9DE4A6384E9C69CB02FFBE7E3CCC0


def test_blink_128A():
    blink = BlinkBlockCipher(
        block_bit_size=128,
        tweak_bit_size=128,
        key_bit_size=1280,
        a=3,
        b=5,
    )

    assert blink.evaluate(
        [KEY_1280, PLAINTEXT, TWEAK_128]
    ) == 0xA227F9DD85E12A8A6CE9DCC03730BBD8


def test_blink_128B():
    blink = BlinkBlockCipher(
        block_bit_size=128,
        tweak_bit_size=256,
        key_bit_size=1280,
        a=3,
        b=5,
    )

    assert blink.evaluate(
        [KEY_1280, PLAINTEXT, TWEAK_256]
    ) == 0xF13AA94C65E193CC095970EF1E22F65E


def test_blink_invalid_configuration():
    with pytest.raises(ValueError, match="Invalid BLINK parameter configuration"):
        BlinkBlockCipher(
            block_bit_size=64,
            tweak_bit_size=64,
            key_bit_size=1024,
            a=2,
            b=3,
        )
