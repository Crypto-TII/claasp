from claasp.ciphers.block_ciphers.trax_block_cipher import TraxBlockCipher


def test_trax_block_cipher():
    trax = TraxBlockCipher()
    assert trax.type == 'block_cipher'
    assert trax.family_name == 'trax'
    assert trax.number_of_rounds == 17
    assert trax.id == 'trax_p256_k256_t128_o256_r17'
    assert trax.component_from(0, 0).id == 'modadd_0_0'


def test_trax_block_cipher_reduced_rounds():
    trax = TraxBlockCipher(number_of_rounds=4)
    assert trax.number_of_rounds == 4
    assert trax.id == 'trax_p256_k256_t128_o256_r4'


def test_trax_block_cipher_evaluate_tv1():
    # Test vector 1: all-zero plaintext, key and tweak.
    # No independently-published numeric test vector for TRAX-L-17 could be found
    # (it is not part of a NIST submission; the designers only publish reference C
    # source code, at https://sparkle-lwc.github.io/trax and Appendix D.2 of
    # [BBBGPUV2020]_). This value was computed with an independent line-by-line
    # Python transcription of that reference C code (traxl17_genkeys_ref /
    # traxl17_enc_ref).
    trax = TraxBlockCipher()
    pt = 0
    key = 0
    tweak = 0
    assert trax.evaluate([pt, key, tweak]) == 0x76e1920dad2b0f289933e3d098dc2e806a7425a2439bafb119daa29e936d8cac


def test_trax_block_cipher_evaluate_tv2():
    # Test vector 2: incremental plaintext/key, non-zero tweak.
    # Computed with the same independent Python port of the reference C code as
    # test vector 1 above; see that test for provenance details.
    trax = TraxBlockCipher()
    pt = int.from_bytes(bytes(range(32)), 'big')
    key = int.from_bytes(bytes(range(32, 64)), 'big')
    tweak = int.from_bytes(bytes(range(16)), 'big')
    assert trax.evaluate([pt, key, tweak]) == 0xe310343a4d030212dca53c766016bcd4987e57bdda5efbcd1eadaa00901dc842
