import time

from claasp.ciphers.block_ciphers.ktantan_block_cipher import KtantanBlockCipher
from claasp.ciphers.block_ciphers.ktantan_fsr_block_cipher import KtantanFSRBlockCipher


def test_ktantan_block_cipher():
    """Gate-level KTANTAN vs FSR-based KTANTAN cross-validation at reduced round count.

    Full test vectors are in ktantan_fsr_block_cipher_test.py (faster implementation).
    Here we verify that the gate-level and FSR implementations agree at 40 rounds
    (enough to exhaust all 80 initial key bits at 2 bits per round).
    """
    ktantan = KtantanBlockCipher()
    assert ktantan.type == 'block_cipher'
    assert ktantan.family_name == 'ktantan'
    assert ktantan.number_of_rounds == 254
    assert ktantan.id == 'ktantan_p32_k80_o32_r254'

    ktantan = KtantanBlockCipher(block_bit_size=64, number_of_rounds=8)
    assert ktantan.number_of_rounds == 8
    assert ktantan.id == 'ktantan_p64_k80_o64_r8'

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
        t0 = time.perf_counter()
        gate = KtantanBlockCipher(block_bit_size=block_size, number_of_rounds=ROUNDS)
        fsr  = KtantanFSRBlockCipher(block_bit_size=block_size, number_of_rounds=ROUNDS)
        t_build = time.perf_counter() - t0

        gate_out = gate.evaluate([pt, key])
        fsr_out  = fsr.evaluate([pt, key])

        t_eval = time.perf_counter() - t0 - t_build
        print(f"\n[ktantan gate vs fsr r={ROUNDS} bs={block_size}] "
              f"build={t_build:.2f}s  eval_total={t_eval:.2f}s  "
              f"gate={gate_out:#x}  fsr={fsr_out:#x}")
        assert gate_out == fsr_out, (
            f"Mismatch at block_size={block_size}: gate={gate_out:#x} fsr={fsr_out:#x}"
        )
