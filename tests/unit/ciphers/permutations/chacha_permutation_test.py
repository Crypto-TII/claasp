from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation


def test_chacha_permutation():
    chacha = ChachaPermutation()
    assert chacha.family_name == 'chacha_permutation'
    assert chacha.type == 'permutation'
    assert chacha.number_of_rounds == 0
    assert chacha.id == 'chacha_permutation_p512_o512_r0'

    chacha = ChachaPermutation(number_of_rounds=2)
    assert chacha.number_of_rounds == 2

    chacha = ChachaPermutation(number_of_rounds=40)
    state = ["61707865", "3320646e", "79622d32", "6b206574",
             "03020100", "07060504", "0b0a0908", "0f0e0d0c",
             "13121110", "17161514", "1b1a1918", "1f1e1d1c",
             "00000001", "09000000", "4a000000", "00000000"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0x837778abe238d763a67ae21e5950bb2fc4f2d0c7fc62bb2f8fa018fc3f5ec7b7335271c2f29489f3eabda8fc82e46ebdd'
                 '19c12b4b04e16de9e83d0cb4e3c50a2', 16)
    assert chacha.evaluate([plaintext], verbosity=False) == output


def test_toy_chacha_permutation():
    """
    The test vectors below were taken from the source code available in the URL specified in [DEY2023]_.
    """

    chacha = ChachaPermutation(number_of_rounds=2, rotations=[2, 1, 4, 3], word_size=8)
    state = ["01", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0x81000000ad0000005600000046000000', 16)
    assert chacha.evaluate([plaintext], verbosity=False) == output

    chacha = ChachaPermutation(number_of_rounds=8, rotations=[2, 1, 4, 3], word_size=8)
    state = ["01", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0xe023858e713feb86a730656ac909f76a', 16)
    assert chacha.evaluate([plaintext], verbosity=False) == output
