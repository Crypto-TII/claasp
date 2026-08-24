from claasp.ciphers.permutations.norx_permutation import NorxPermutation


def test_norx_permutation():
    norx = NorxPermutation()
    assert norx.family_name == 'norx'
    assert norx.type == 'permutation'
    assert norx.number_of_rounds == 4
    assert norx.word_bit_size == 32
    assert norx.id == 'norx_p512_o512_r4'
    assert norx.component_from(0, 0).id == 'and_0_0'

    norx = NorxPermutation(number_of_rounds=6, word_size=64)
    assert norx.number_of_rounds == 6
    assert norx.word_bit_size == 64
    assert norx.id == 'norx_p1024_o1024_r6'


def test_norx_permutation_official_test_vectors():
    """
    NORX v3.0 specification [AJN2016]_, Appendix A.1 ("Traces for F"), states that an
    implementation of the raw permutation F can be verified by checking that
    ``(u0, ..., u15) = F^2(0, ..., 15)``, where ``F^2`` denotes two rounds of F applied to the state with
    word ``i`` set to the integer ``i``. The expected ``u0, ..., u15`` values are listed in Table 3.4 of the
    same document (https://competitions.cr.yp.to/round3/norxv30.pdf).
    """
    state_32 = int(''.join(format(i, '032b') for i in range(16)), 2)
    u_32 = [0x0454EDAB, 0xAC6851CC, 0xB707322F, 0xA0C7C90D, 0x99AB09AC, 0xA643466D, 0x21C22362, 0x1230C950,
            0xA3D8D930, 0x3FA8B72C, 0xED84EB49, 0xEDCA4787, 0x335463EB, 0xF994220B, 0xBE0BF5C9, 0xD7C49104]
    expected_32 = int(''.join(format(w, '032b') for w in u_32), 2)
    norx32 = NorxPermutation(number_of_rounds=2, word_size=32)
    assert norx32.evaluate([state_32]) == expected_32

    state_64 = int(''.join(format(i, '064b') for i in range(16)), 2)
    u_64 = [0xE4D324772B91DF79, 0x3AEC9ABAAEB02CCB, 0x9DFBA13DB4289311, 0xEF9EB4BF5A97F2C8,
            0x3F466E92C1532034, 0xE6E986626CC405C1, 0xACE40F3B549184E1, 0xD9CFD35762614477,
            0xB15E641748DE5E6B, 0xAA95E955E10F8410, 0x28D1034441A9DD40, 0x7F31BBF964E93BF5,
            0xB5E9E22493DFFB96, 0xB980C852479FAFBD, 0xDA24516BF55EAFD4, 0x86026AE8536F1501]
    expected_64 = int(''.join(format(w, '064b') for w in u_64), 2)
    norx64 = NorxPermutation(number_of_rounds=2, word_size=64)
    assert norx64.evaluate([state_64]) == expected_64
