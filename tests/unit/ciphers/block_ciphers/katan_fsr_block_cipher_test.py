from claasp.ciphers.block_ciphers.katan_fsr_block_cipher import KatanFSRBlockCipher


def test_katan_fsr_block_cipher():
    """Test vectors for the KATAN FSR block cipher.

    The expected values are identical to those of the gate-level KatanBlockCipher,
    confirming that both implementations produce the same results.
    """
    katan_fsr = KatanFSRBlockCipher()
    assert katan_fsr.type == 'block_cipher'
    assert katan_fsr.family_name == 'katan_fsr'
    assert katan_fsr.number_of_rounds == 254
    assert katan_fsr.id == 'katan_fsr_p32_k80_o32_r254'

    katan_fsr = KatanFSRBlockCipher(block_bit_size=48, number_of_rounds=4)
    assert katan_fsr.number_of_rounds == 4
    assert katan_fsr.id == 'katan_fsr_p48_k80_o48_r4'

    # Reuse cipher objects per block size to minimise Python code compilation.
    katan_fsr32 = KatanFSRBlockCipher()
    katan_fsr48 = KatanFSRBlockCipher(block_bit_size=48)
    katan_fsr64 = KatanFSRBlockCipher(block_bit_size=64)

    key_all = 0xFFFFFFFFFFFFFFFFFFFF
    assert katan_fsr32.evaluate([0x00000000, key_all]) == 0x7E1FF945
    assert katan_fsr48.evaluate([0x00000000, key_all]) == 0x4B7EFCFB8659
    assert katan_fsr64.evaluate([0x00000000, key_all]) == 0x21F2E99C0FAB828A

    key2 = 0x0123456789ABCDEFFEDC
    assert katan_fsr32.evaluate([0x12345678, key2]) == 0xCFFDC7DA
    assert katan_fsr48.evaluate([0x123456789ABC, key2]) == 0x0675F0F5DA84
    assert katan_fsr64.evaluate([0x123456789ABCDEF0, key2]) == 0x0B3EDCA9A41D4619
