from claasp.ciphers.single_component_ciphers.not_permutation import NotPermutation


def test_not_permutation_properties():
    not_permutation = NotPermutation(bit_size=8)
    assert not_permutation.type == 'permutation'
    assert not_permutation.id == 'not_permutation_p8_o8_r1'
    assert not_permutation.component_from(0, 0).id == 'not_0_0'

    value = 0x3C
    output = not_permutation.evaluate([value])
    assert output == 0xC3

    inverse = NotPermutation(bit_size=8)
    assert inverse.evaluate([output]) == value
