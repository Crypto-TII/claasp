import pytest

from claasp.ciphers.block_ciphers.ktantan_block_cipher import KtantanBlockCipher
from claasp.ciphers.block_ciphers.ktantan_fsr_block_cipher import KtantanFSRBlockCipher


def test_ktantan_block_cipher():
    """Gate-level KTANTAN vs FSR-based KTANTAN cross-validation at reduced round count.

    Official test vectors for the KTANTAN block cipher are not available.
    The full 254-round test vectors were generated from the implementations provided in:
    https://gist.github.com/raullenchai/2662701
    https://gist.github.com/raullenchai/2712516

    Full test vectors are in ktantan_fsr_block_cipher_test.py (faster implementation).
    Here we verify that the gate-level and FSR implementations agree at 8 rounds,
    which is enough to hit both IR-controlled branches (IR[0] = 1 and IR[7] = 0),
    exercise the round-output path, and cover the relevant fixed-key mux-schedule
    branches, while keeping the cross-check much cheaper than the full 254-round
    test.
    """
    ktantan = KtantanBlockCipher()
    assert ktantan.type == 'block_cipher'
    assert ktantan.family_name == 'ktantan'
    assert ktantan.number_of_rounds == 254
    assert ktantan.id == 'ktantan_p32_k80_o32_r254'

    ktantan = KtantanBlockCipher(block_bit_size=64, number_of_rounds=8)
    assert ktantan.number_of_rounds == 8
    assert ktantan.id == 'ktantan_p64_k80_o64_r8'

    # Eight rounds cover both IR branches and the relevant key-schedule mux cases.
    ROUNDS = 8
    inputs = [
        (32,  0x00000000,         0xFFFFFFFFFFFFFFFFFFFF),
        (32,  0x12345678,         0x0123456789ABCDEFFEDC),
        (48,  0x000000000000,     0xFFFFFFFFFFFFFFFFFFFF),
        (48,  0x123456789ABC,     0x0123456789ABCDEFFEDC),
        (64,  0x0000000000000000, 0xFFFFFFFFFFFFFFFFFFFF),
        (64,  0x123456789ABCDEF0, 0x0123456789ABCDEFFEDC),
    ]

    for block_size, pt, key in inputs:
        gate = KtantanBlockCipher(block_bit_size=block_size, number_of_rounds=ROUNDS)
        fsr  = KtantanFSRBlockCipher(block_bit_size=block_size, number_of_rounds=ROUNDS)

        gate_out = gate.evaluate([pt, key])
        fsr_out  = fsr.evaluate([pt, key])

        assert gate_out == fsr_out, (
            f"Mismatch at block_size={block_size}: gate={gate_out:#x} fsr={fsr_out:#x}"
        )


def test_ktantan_block_cipher_round_validation():
    with pytest.raises(ValueError, match="must be positive"):
        KtantanBlockCipher(number_of_rounds=0)

    with pytest.raises(TypeError, match="must be an integer"):
        KtantanBlockCipher(number_of_rounds=True)

    with pytest.raises(ValueError, match="exceeds the available IR sequence length"):
        KtantanBlockCipher(number_of_rounds=255)

    ktantan = KtantanBlockCipher(number_of_rounds=255, ir_mode="cycle")
    assert ktantan.number_of_rounds == 255

    with pytest.raises(ValueError, match="ir_mode must be one of"):
        KtantanBlockCipher(number_of_rounds=255, ir_mode="invalid")
