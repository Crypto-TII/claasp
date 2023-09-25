from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation


def test_salsa_permutation():
    salsa = SalsaPermutation()
    assert salsa.family_name == 'salsa_permutation'
    assert salsa.type == 'permutation'
    assert salsa.number_of_rounds == 0
    assert salsa.id == 'salsa_permutation_p512_o512_r0'

    salsa = SalsaPermutation(number_of_rounds=4)
    assert salsa.number_of_rounds == 4

    salsa = SalsaPermutation(number_of_rounds=4)
    state = ["00000001", "00000000", "00000000", "00000000",
             "00000000", "00000000", "00000000", "00000000",
             "00000000", "00000000", "00000000", "00000000",
             "00000000", "00000000", "00000000", "00000000"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0x8186a22d0040a2848247921006929051080000900240220000004000008000000001020020400000080081040000'
                 '000020500000a00000400008180a612a8020', 16)
    assert salsa.evaluate([plaintext], verbosity=False) == output

    salsa = SalsaPermutation(number_of_rounds=4)
    state = ["de501066", "6f9eb8f7", "e4fbbd9b", "454e3f57",
             "b75540d3", "43e93a4c", "3a6f2aa0", "726d6b36",
             "9243f484", "9145d1e8", "4fa9d247", "dc8dee11",
             "054bf545", "254dd653", "d9421b6d", "67b276c1"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0xccaaf67223d960f79153e63acd9a60d050440492f07cad19ae344aa0df4cfdfcca531c298e7943dbac1680cdd503'
                 'ca00a74b2ad6bc331c5c1dda24c7ee928277', 16)
    assert salsa.evaluate([plaintext], verbosity=False) == output
