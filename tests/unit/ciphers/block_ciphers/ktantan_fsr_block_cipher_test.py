import time

from claasp.ciphers.block_ciphers.ktantan_fsr_block_cipher import KtantanFSRBlockCipher


def test_ktantan_fsr_block_cipher():
    """Test vectors for the KTANTAN FSR block cipher.

    The expected values are identical to those of the gate-level KtantanBlockCipher,
    confirming that both implementations produce the same results.
    """
    ktantan_fsr = KtantanFSRBlockCipher()
    assert ktantan_fsr.type == 'block_cipher'
    assert ktantan_fsr.family_name == 'ktantan_fsr'
    assert ktantan_fsr.number_of_rounds == 254
    assert ktantan_fsr.id == 'ktantan_fsr_p32_k80_o32_r254'

    ktantan_fsr = KtantanFSRBlockCipher(block_bit_size=64, number_of_rounds=8)
    assert ktantan_fsr.number_of_rounds == 8
    assert ktantan_fsr.id == 'ktantan_fsr_p64_k80_o64_r8'

    # Reuse cipher objects per block size to minimise Python code compilation.
    t0 = time.perf_counter()
    ktantan_fsr32 = KtantanFSRBlockCipher()
    ktantan_fsr48 = KtantanFSRBlockCipher(block_bit_size=48)
    ktantan_fsr64 = KtantanFSRBlockCipher(block_bit_size=64)
    t_build = time.perf_counter() - t0

    key_all = 0xFFFFFFFFFFFFFFFFFFFF
    assert ktantan_fsr32.evaluate([0x00000000, key_all]) == 0x22EA3988
    assert ktantan_fsr48.evaluate([0x00000000, key_all]) == 0x936D0FA33A05
    assert ktantan_fsr64.evaluate([0x00000000, key_all]) == 0xC02DE05BFA194B16

    key2 = 0x0123456789ABCDEFFEDC
    assert ktantan_fsr32.evaluate([0x12345678, key2]) == 0xB3F16EA2
    assert ktantan_fsr48.evaluate([0x123456789ABC, key2]) == 0xEC5D5700FD6A
    assert ktantan_fsr64.evaluate([0x123456789ABCDEF0, key2]) == 0xD2E6ABB1BDBCB6CC

    print(f"\n[ktantan_fsr] build: {t_build:.2f}s")
