import pytest

from claasp.ciphers.block_ciphers.katan_block_cipher import KatanBlockCipher
from claasp.ciphers.block_ciphers.katan_fsr_block_cipher import KatanFSRBlockCipher


def test_katan_block_cipher():
    """Gate-level KATAN vs FSR-based KATAN cross-validation at reduced round count.

    Official test vectors for the KATAN block cipher are not available.
    The full 254-round test vectors were generated from the implementations provided in:
    https://gist.github.com/raullenchai/2662701
    https://gist.github.com/raullenchai/2712516

    Full test vectors are in katan_fsr_block_cipher_test.py (faster implementation).
    Here we verify that the gate-level and FSR implementations agree at 41 rounds,
    which is the first point where KATAN needs to extend its round-key stream past
    the initial 80 key bits while still keeping the cross-check much cheaper than
    the full 254-round test.
    """
    katan = KatanBlockCipher()
    assert katan.type == 'block_cipher'
    assert katan.family_name == 'katan'
    assert katan.number_of_rounds == 254
    assert katan.id == 'katan_p32_k80_o32_r254'

    katan = KatanBlockCipher(block_bit_size=48, number_of_rounds=4)
    assert katan.number_of_rounds == 4
    assert katan.id == 'katan_p48_k80_o48_r4'

    # Forty-one rounds are enough to trigger the first key-LFSR extension step.
    ROUNDS = 41
    inputs = [
        (32,  0x00000000,         0xFFFFFFFFFFFFFFFFFFFF),
        (32,  0x12345678,         0x0123456789ABCDEFFEDC),
        (48,  0x000000000000,     0xFFFFFFFFFFFFFFFFFFFF),
        (48,  0x123456789ABC,     0x0123456789ABCDEFFEDC),
        (64,  0x0000000000000000, 0xFFFFFFFFFFFFFFFFFFFF),
        (64,  0x123456789ABCDEF0, 0x0123456789ABCDEFFEDC),
    ]

    for block_size, pt, key in inputs:
        gate = KatanBlockCipher(block_bit_size=block_size, number_of_rounds=ROUNDS)
        fsr  = KatanFSRBlockCipher(block_bit_size=block_size, number_of_rounds=ROUNDS)

        gate_out = gate.evaluate([pt, key])
        fsr_out  = fsr.evaluate([pt, key])

        assert gate_out == fsr_out, (
            f"Mismatch at block_size={block_size}: gate={gate_out:#x} fsr={fsr_out:#x}"
        )


def test_katan_block_cipher_round_validation():
    with pytest.raises(ValueError, match="must be positive"):
        KatanBlockCipher(number_of_rounds=0)

    with pytest.raises(TypeError, match="must be an integer"):
        KatanBlockCipher(number_of_rounds=True)

    with pytest.raises(ValueError, match="exceeds the available IR sequence length"):
        KatanBlockCipher(number_of_rounds=255)

    katan = KatanBlockCipher(number_of_rounds=255, ir_mode="cycle")
    assert katan.number_of_rounds == 255

    with pytest.raises(ValueError, match="ir_mode must be one of"):
        KatanBlockCipher(number_of_rounds=255, ir_mode="invalid")