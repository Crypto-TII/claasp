from claasp.ciphers.permutations.alzette_permutation import AlzettePermutation, SPARKLE_CONSTANTS


def test_alzette_permutation():
    alzette = AlzettePermutation()
    assert alzette.family_name == 'alzette'
    assert alzette.type == 'permutation'
    assert alzette.number_of_rounds == 4
    assert alzette.id == 'alzette_p64_o64_r4'
    assert alzette.component_from(0, 0).id == 'constant_0_0'

    assert alzette.evaluate([0x0000000000000000]) == 0x44dd4de9e5581f2d

    alzette_c1 = AlzettePermutation(round_constant=SPARKLE_CONSTANTS[1])
    assert alzette_c1.id == 'alzette_p64_o64_r4'
    assert alzette_c1.evaluate([0x0000000000000000]) != 0x44dd4de9e5581f2d
