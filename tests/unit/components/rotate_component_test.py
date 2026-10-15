from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
from claasp.components.rotate_component import Rotate
from claasp.name_mappings import XOR_DIFFERENTIAL


def test_algebraic_polynomials():
    cipher = RotateCipher(bit_size=6, rotation_amount=3)
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


def _rotate(amount, bit_size=8):
    return Rotate(0, 0, ['input'], [list(range(bit_size))], bit_size, amount)


def test_rotation_amount_beyond_word_size_wraps_around():
    # Keccak-p[200] applies rho offsets such as -15 to 8-bit lanes: -15 == 1 (mod 8), a rotation by one position.
    big, small, identity = _rotate(-15), _rotate(1), _rotate(0)
    for method in ("sat_constraints", "sat_xor_linear_mask_propagation_constraints",
                   "sat_bitwise_deterministic_truncated_xor_differential_constraints",
                   "smt_constraints", "smt_xor_linear_mask_propagation_constraints"):
        assert getattr(big, method)() == getattr(small, method)(), method
        assert getattr(big, method)() != getattr(identity, method)(), method
        assert getattr(_rotate(8), method)() == getattr(identity, method)(), method
        assert getattr(_rotate(-9), method)() == getattr(_rotate(-1), method)(), method


def test_milp_rotation_amount_beyond_word_size_wraps_around():
    for method in ("milp_constraints", "milp_xor_linear_mask_propagation_constraints"):
        rendered = []
        for amount in (-15, 1, 0):
            cipher = RotateCipher(bit_size=8, rotation_amount=amount)
            milp = MilpModel(cipher)
            milp.init_model_in_sage_milp_class()
            _, constraints = getattr(cipher.component_from(0, 0), method)(milp)
            rendered.append([str(c) for c in constraints])
        assert rendered[0] == rendered[1], method
        assert rendered[0] != rendered[2], method


def test_sat_trail_of_large_rotation_matches_evaluation():
    cipher = RotateCipher(bit_size=8, rotation_amount=-15)
    plaintext = set_fixed_variables("plaintext", "equal", list(range(8)), integer_to_bit_list(0x40, 8, 'big'))
    sat = SatXorDifferentialModel(cipher)
    sat.build_xor_differential_trail_model(weight=-1, fixed_variables=[plaintext])
    solution = sat.solve(XOR_DIFFERENTIAL)
    expected = cipher.evaluate([0x40]) ^ cipher.evaluate([0])
    assert expected == 0x20
    assert int(solution["components_values"]["cipher_output_0_1"]["value"], 16) == expected
