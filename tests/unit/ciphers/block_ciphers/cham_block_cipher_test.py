"""
Tests for ChamBlockCipher.

Test vectors for CHAM-64/128 and CHAM-128/128 are taken from Appendix A of

.. [RohCHAM2018] Roh, D., Koo, B., Jung, Y., Jeong, I. R., Lee, J. W., Kwon,
   D., & Kim, W. H. (2019). Revised version of block cipher CHAM. In
   Information Security and Cryptology – ICISC 2019, LNCS 11975,
   Springer, pp. 1–19.  https://doi.org/10.1007/978-3-030-40921-0_1

.. [JeongCHAM2020] Jeong, I. R., & Lee, J. W. (2020). Revised version of
   block cipher CHAM. In ICISC 2019, LNCS 11975, Springer.

All three variants (CHAM-64/128, CHAM-128/128, CHAM-128/256) are tested at
both the original round count (from [RohCHAM2018]_) and the revised round count
(from [JeongCHAM2020]_).
"""

from claasp.ciphers.block_ciphers.cham_block_cipher import ChamBlockCipher


# ---------------------------------------------------------------------------
# Shared test inputs (MSW-first word concatenation, as per the papers)
# ---------------------------------------------------------------------------
_KEY_64_128  = 0x010003020504070609080b0a0d0c0f0e   # 128-bit
_PT_64       = 0x1100332255447766                   # 64-bit

_KEY_128_128 = 0x03020100070605040b0a09080f0e0d0c   # 128-bit
_PT_128      = 0x3322110077665544bbaa9988ffeeddcc   # 128-bit

_KEY_128_256 = (                                    # 256-bit
    0x03020100070605040b0a09080f0e0d0c
    << 128
    | 0xf3f2f1f0f7f6f5f4fbfaf9f8fffefdfc
)


def test_cham_block_cipher_structure():
    cham = ChamBlockCipher()
    assert cham.type == 'block_cipher'
    assert cham.family_name == 'cham_block_cipher'
    assert cham.number_of_rounds == 88
    assert cham.id == 'cham_block_cipher_k128_p64_o64_r88'
    # Round 0 first component: ROL(k[0], 1) from the key schedule
    assert cham.component_from(0, 0).id == 'rot_0_0'

    cham4 = ChamBlockCipher(number_of_rounds=4)
    assert cham4.number_of_rounds == 4
    assert cham4.id == 'cham_block_cipher_k128_p64_o64_r4'
    assert cham4.component_from(3, 0).id == 'constant_3_0'


def test_cham_64_128():
    """CHAM-64/128: original (r=80) and revised (r=88) test vectors."""
    # Original CHAM, 80 rounds [RohCHAM2018]_
    cham_80 = ChamBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=80)
    assert cham_80.evaluate([_KEY_64_128, _PT_64]) == 0x453c63bcdcfabf4e

    # Revised CHAM, 88 rounds (default) [JeongCHAM2020]_
    cham_88 = ChamBlockCipher()
    assert cham_88.evaluate([_KEY_64_128, _PT_64]) == 0x65791204123fe5a9
    assert cham_88.evaluate_vectorized([_KEY_64_128, _PT_64], evaluate_api=True) == 0x65791204123fe5a9


def test_cham_128_128():
    """CHAM-128/128: original (r=80) and revised (r=112) test vectors."""
    # Original CHAM-128/128, 80 rounds [RohCHAM2018]_
    cham_80 = ChamBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=80)
    assert cham_80.evaluate([_KEY_128_128, _PT_128]) == 0xc3746034b55700c58d64ec32489332f7

    # Revised CHAM-128/128, 112 rounds [JeongCHAM2020]_
    cham_112 = ChamBlockCipher(block_bit_size=128, key_bit_size=128)
    assert cham_112.number_of_rounds == 112
    assert cham_112.evaluate([_KEY_128_128, _PT_128]) == 0xd05419ee9f118f4c99e364691c885ec1
    assert cham_112.evaluate_vectorized([_KEY_128_128, _PT_128], evaluate_api=True) == \
        0xd05419ee9f118f4c99e364691c885ec1


def test_cham_128_256():
    """CHAM-128/256: original (r=96) and revised (r=120) test vectors."""
    # Original CHAM-128/256, 96 rounds [RohCHAM2018]_
    cham_96 = ChamBlockCipher(block_bit_size=128, key_bit_size=256, number_of_rounds=96)
    assert cham_96.evaluate([_KEY_128_256, _PT_128]) == 0xa899c8a0c929d55cab670d380c4f7ac8

    # Revised CHAM-128/256, 120 rounds [JeongCHAM2020]_
    cham_120 = ChamBlockCipher(block_bit_size=128, key_bit_size=256)
    assert cham_120.number_of_rounds == 120
    assert cham_120.evaluate([_KEY_128_256, _PT_128]) == 0x027377dc120b56518f839b955e5ec075
    assert cham_120.evaluate_vectorized([_KEY_128_256, _PT_128], evaluate_api=True) == \
        0x027377dc120b56518f839b955e5ec075
