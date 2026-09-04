from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
from claasp.components.rotate_component import Rotate
from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)

def test_algebraic_polynomials():
    cipher = RotateCipher(bit_size=6, parameter=3)
    rotate_component = cipher.component_from(0, 0)
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = rotate_component.algebraic_polynomials(algebraic)

    assert len(algebraic_polynomials) == 6
    assert str(algebraic_polynomials[0]) == "rot_0_0_y0 + rot_0_0_x3"
    assert str(algebraic_polynomials[-1]) == "rot_0_0_y5 + rot_0_0_x2"


def test_cp_inverse_constraints():
    rotate_component = Rotate(0, 0, ['plaintext'], [list(range(16))], 16, 7)
    declarations, constraints = rotate_component.cp_inverse_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint rot_0_0_inverse[0] = plaintext[9];'
    assert constraints[-1] == 'constraint rot_0_0_inverse[15] = plaintext[8];'


def test_cp_xor_differential_first_step_constraints():
    rotate_component = Rotate(0, 18, ['input0', 'input1', 'input2', 'input3'],
                              [[0, 1, 2, 3, 4, 5, 6, 7],
                               [0, 1, 2, 3, 4, 5, 6, 7],
                               [0, 1, 2, 3, 4, 5, 6, 7],
                               [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)

    class DummyModel:
        word_size = 8

    declarations, constraints = rotate_component.cp_xor_differential_first_step_constraints(DummyModel())

    assert declarations == ['array[0..3] of var 0..1: rot_0_18;']

    assert constraints == ['constraint rot_0_18[0] = input1[0];', 'constraint rot_0_18[1] = input2[0];',
                           'constraint rot_0_18[2] = input3[0];', 'constraint rot_0_18[3] = input0[0];']


def test_smt_xor_quasidifferential_propagation_constraints():
    cipher = RotateCipher(bit_size=2, parameter=1)
    model = SmtXorQuasidifferentialModel(cipher)
    rotate_component = cipher.component_from(0, 0)
    variables, constraints = rotate_component.smt_xor_quasidifferential_propagation_constraints(model)

    assert variables == ['rot_0_0_0', 'rot_0_0_1', 'qdt_rot_0_0_0', 'qdt_rot_0_0_1']

    assert constraints == ['(assert (= rot_0_0_0 plaintext_1))',
                           '(assert (= rot_0_0_1 plaintext_0))',
                           '(assert (= qdt_rot_0_0_0 qdt_plaintext_1))',
                           '(assert (= qdt_rot_0_0_1 qdt_plaintext_0))']