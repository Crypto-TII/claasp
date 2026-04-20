from claasp.ciphers.block_ciphers.katan_block_cipher import KatanBlockCipher
from claasp.ciphers.block_ciphers.katan_fsr_block_cipher import KatanFSRBlockCipher


def test_katan_block_cipher():
    """Gate-level KATAN vs FSR-based KATAN cross-validation at reduced round count.

    Full test vectors are in katan_fsr_block_cipher_test.py (faster implementation).
    Here we verify that the gate-level and FSR implementations agree at 40 rounds
    (enough to exhaust all 80 initial key bits at 2 bits per round).
    """
    katan = KatanBlockCipher()
    assert katan.type == 'block_cipher'
    assert katan.family_name == 'katan'
    assert katan.number_of_rounds == 254
    assert katan.id == 'katan_p32_k80_o32_r254'

    katan = KatanBlockCipher(block_bit_size=48, number_of_rounds=4)
    assert katan.number_of_rounds == 4
    assert katan.id == 'katan_p48_k80_o48_r4'

    # Cross-validate gate-level vs FSR at 40 rounds (all 80 key bits consumed).
    ROUNDS = 40
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