from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


def test_algebraic_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=2)
    rotate_component = fancy.get_component_from_id("rot_1_11")
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = rotate_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials) == "[rot_1_11_y0 + rot_1_11_x3, rot_1_11_y1 + rot_1_11_x4," \
                                         " rot_1_11_y2 + rot_1_11_x5, rot_1_11_y3 + rot_1_11_x0," \
                                         " rot_1_11_y4 + rot_1_11_x1, rot_1_11_y5 + rot_1_11_x2]"


def test_cp_inverse_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    rotate_component = speck.component_from(0, 0)
    declarations, constraints = rotate_component.cp_inverse_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint rot_0_0_inverse[0] = plaintext[9];'
    assert constraints[-1] == 'constraint rot_0_0_inverse[15] = plaintext[8];'


def test_cp_xor_differential_first_step_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = MznModel(aes)
    rotate_component = aes.component_from(0, 18)
    declarations, constraints = rotate_component.cp_xor_differential_first_step_constraints(cp)

    assert declarations == ['array[0..3] of var 0..1: rot_0_18;']

    assert constraints == ['constraint rot_0_18[0] = sbox_0_6[0];', 'constraint rot_0_18[1] = sbox_0_10[0];',
                           'constraint rot_0_18[2] = sbox_0_14[0];', 'constraint rot_0_18[3] = sbox_0_2[0];']
