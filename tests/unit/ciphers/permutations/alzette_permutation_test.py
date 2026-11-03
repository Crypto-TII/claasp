from claasp.ciphers.permutations.alzette_permutation import AlzettePermutation, SPARKLE_CONSTANTS


def test_alzette_permutation():
    alzette = AlzettePermutation()
    assert alzette.family_name == 'alzette'
    assert alzette.type == 'permutation'
    assert alzette.number_of_rounds == 4
    assert alzette.id == 'alzette_p64_o64_r4'
    assert alzette.component_from(0, 0).id == 'constant_0_0'

    # Test vectors below are cross-checked against an independent re-implementation
    # of the ARXBOX macro from the designers' own reference implementation of
    # SPARKLE (submitted to the NIST Lightweight Cryptography project), see
    # https://github.com/cryptolu/sparkle/blob/master/software/sparkle/sparkle.c
    assert alzette.evaluate([0x0000000000000000]) == 0x44dd4de9e5581f2d
    assert alzette.evaluate([0xdeadbeefcafebabe]) == 0x9d50490c3a596770

    alzette_c1 = AlzettePermutation(round_constant=SPARKLE_CONSTANTS[1])
    assert alzette_c1.id == 'alzette_p64_o64_r4'
    assert alzette_c1.evaluate([0x0123456789abcdef]) == 0x6aa7eb426bcd187d
    assert alzette_c1.evaluate([0x0000000000000000]) != 0x44dd4de9e5581f2d
