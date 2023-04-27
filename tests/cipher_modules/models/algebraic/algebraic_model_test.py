from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.algebraic.boolean_polynomial_ring import is_boolean_polynomial_ring


def test_connection_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=1)
    connection = AlgebraicModel(fancy).connection_polynomials()
    assert str(connection[:24]) == '[plaintext_y0 + sbox_0_0_x0, plaintext_y1 + sbox_0_0_x1, ' \
                                   'plaintext_y2 + sbox_0_0_x2, plaintext_y3 + sbox_0_0_x3, ' \
                                   'plaintext_y4 + sbox_0_1_x0, plaintext_y5 + sbox_0_1_x1, ' \
                                   'plaintext_y6 + sbox_0_1_x2, plaintext_y7 + sbox_0_1_x3, ' \
                                   'plaintext_y8 + sbox_0_2_x0, plaintext_y9 + sbox_0_2_x1, ' \
                                   'plaintext_y10 + sbox_0_2_x2, plaintext_y11 + sbox_0_2_x3, ' \
                                   'plaintext_y12 + sbox_0_3_x0, plaintext_y13 + sbox_0_3_x1, ' \
                                   'plaintext_y14 + sbox_0_3_x2, plaintext_y15 + sbox_0_3_x3, ' \
                                   'plaintext_y16 + sbox_0_4_x0, plaintext_y17 + sbox_0_4_x1, ' \
                                   'plaintext_y18 + sbox_0_4_x2, plaintext_y19 + sbox_0_4_x3, ' \
                                   'plaintext_y20 + sbox_0_5_x0, plaintext_y21 + sbox_0_5_x1, ' \
                                   'plaintext_y22 + sbox_0_5_x2, plaintext_y23 + sbox_0_5_x3]'


def test_nvars():
    fancy = FancyBlockCipher(number_of_rounds=1)
    assert AlgebraicModel(fancy).nvars() == 96


def test_polynomial_system():
    fancy = FancyBlockCipher(number_of_rounds=1)
    assert str(AlgebraicModel(fancy).polynomial_system()) == \
           'Polynomial Sequence with 468 Polynomials in 384 Variables'


def test_polynomial_system_at_round():
    fancy = FancyBlockCipher(number_of_rounds=1)
    assert str(AlgebraicModel(fancy).polynomial_system_at_round(0)) == \
           'Polynomial Sequence with 252 Polynomials in 288 Variables'


def test_ring():
    fancy = FancyBlockCipher(number_of_rounds=1)
    ring = AlgebraicModel(fancy).ring()
    assert is_boolean_polynomial_ring(ring)

    assert ring.ngens() == 432


def test_var_names():
    fancy = FancyBlockCipher(number_of_rounds=1)
    var_names = AlgebraicModel(fancy).var_names()
    assert var_names[0] == 'sbox_0_0_x0'
