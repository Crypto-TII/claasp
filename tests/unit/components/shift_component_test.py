from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import (
    MilpWordwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
from claasp.components.shift_component import Shift
from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)

def make_shift_component(bit_size=32, parameter=4):
    return Shift(0, 0, ['plaintext'], [list(range(bit_size))], bit_size, parameter)


def test_algebraic_polynomials():
    cipher = ShiftCipher(bit_size=6, parameter=3)
    shift_component = cipher.component_from(0, 0)
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = shift_component.algebraic_polynomials(algebraic)

    assert len(algebraic_polynomials) == 6
    assert str(algebraic_polynomials[0]) == 'shift_0_0_y0'
    assert str(algebraic_polynomials[-1]) == 'shift_0_0_y5 + shift_0_0_x2'


def test_cms_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    output_bit_ids, constraints = shift_component.cms_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert output_bit_ids[-1] == 'shift_0_0_31'
    assert 'shift_0_0_31' in constraints[-1]


def test_cp_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    declarations, constraints = shift_component.cp_constraints()

    assert declarations == []
    assert constraints[0].startswith('constraint shift_0_0[0] = ')
    assert constraints[-1].startswith('constraint shift_0_0[31] = ')


def test_cp_inverse_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    declarations, constraints = shift_component.cp_inverse_constraints()

    assert declarations == []
    assert constraints[0].startswith('constraint shift_0_0_inverse[0] = ')
    assert constraints[-1].startswith('constraint shift_0_0_inverse[31] = ')


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    class DummyModel:
        word_size = 8

    shift_component = Shift(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                            [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                             [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
    declarations, constraints = shift_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())

    assert declarations == []
    assert constraints[0] == 'constraint shift_0_18_active[0] = sbox_0_6_active[0];'
    assert constraints[-1] == 'constraint shift_0_18_value[3] = 0;'


def test_cp_xor_differential_first_step_constraints():
    class DummyModel:
        word_size = 8

    shift_component = Shift(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                            [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                             [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
    declarations, constraints = shift_component.cp_xor_differential_first_step_constraints(DummyModel())

    assert declarations == ['array[0..3] of var 0..1: shift_0_18;']
    assert constraints == ['constraint shift_0_18[0] = sbox_0_6[0];',
                           'constraint shift_0_18[1] = sbox_0_10[0];',
                           'constraint shift_0_18[2] = sbox_0_14[0];',
                           'constraint shift_0_18[3] = 0;']


def test_cp_xor_linear_mask_propagation_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    declarations, constraints = shift_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..31] of var 0..1: shift_0_0_i;', 'array[0..31] of var 0..1: shift_0_0_o;']
    assert len(constraints) > 0
    assert constraints[0].startswith('constraint shift_0_0_')
    assert constraints[-1].endswith(';')


def test_milp_constraints():
    cipher = ShiftCipher(bit_size=8, parameter=4)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    shift_component = cipher.component_from_id('shift_0_0')
    variables, constraints = shift_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[-1]) == "('x[shift_0_0_7]', x_15)"
    assert len(constraints) == 8
    assert str(constraints[-1]).startswith('x_15 == ')


def test_milp_xor_linear_mask_propagation_constraints():
    cipher = ShiftCipher(bit_size=8, parameter=4)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    shift_component = cipher.component_from_id('shift_0_0')
    variables, constraints = shift_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[shift_0_0_0_i]', x_0)"
    assert str(variables[-1]) == "('x[shift_0_0_7_o]', x_15)"
    assert len(constraints) == 8
    assert str(constraints[0]).endswith('== 0')


def test_minizinc_constraints():
    cipher = ShiftCipher(bit_size=32, parameter=4)
    minizinc = MznModel(cipher)
    shift_component = cipher.component_from_id('shift_0_0')
    _, shift_mzn_constraints = shift_component.minizinc_constraints(minizinc)

    assert shift_mzn_constraints[0].startswith('constraint ')
    assert 'SHIFT(' in shift_mzn_constraints[0]
    assert 'shift_0_0_x0' in shift_mzn_constraints[0]
    assert 'shift_0_0_y31' in shift_mzn_constraints[0]


def test_sat_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    output_bit_ids, constraints = shift_component.sat_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert output_bit_ids[-1] == 'shift_0_0_31'
    assert 'shift_0_0_31' in constraints[-1]


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    output_bit_ids, constraints = shift_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0_0'
    assert output_bit_ids[-1] == 'shift_0_0_31_1'
    assert 'shift_0_0_31_1' in constraints[-1]


def test_sat_xor_linear_mask_propagation_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    output_bit_ids, constraints = shift_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0_i'
    assert output_bit_ids[-1] == 'shift_0_0_31_o'
    assert 'shift_0_0_31_i' in constraints[-1]


def test_smt_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    output_bit_ids, constraints = shift_component.smt_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert output_bit_ids[-1] == 'shift_0_0_31'
    assert constraints[0].startswith('(assert ')
    assert constraints[-1].startswith('(assert ')

    shift_component = make_shift_component(bit_size=32, parameter=-5)
    output_bit_ids, constraints = shift_component.smt_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert constraints[0].startswith('(assert ')
    assert constraints[5].startswith('(assert ')


def test_smt_xor_linear_mask_propagation_constraints():
    shift_component = make_shift_component(bit_size=32, parameter=4)
    output_bit_ids, constraints = shift_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0_i'
    assert output_bit_ids[-1] == 'shift_0_0_31_o'
    assert constraints[0].startswith('(assert ')
    assert constraints[-1].startswith('(assert ')

    shift_component = make_shift_component(bit_size=32, parameter=-5)
    output_bit_ids, constraints = shift_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0_i'
    assert constraints[0].startswith('(assert ')
    assert constraints[-1].startswith('(assert ')


def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = ShiftCipher(bit_size=8, parameter=4)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    shift_component = cipher.component_from_id('shift_0_0')
    variables, constraints = shift_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[-1]) == "('x_class[shift_0_0_7]', x_15)"
    assert str(constraints[-1]).startswith('x_15 == ')


def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    cipher = ShiftCipher(bit_size=32, parameter=-8)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    shift_component = Shift(0, 18, ['in0', 'in1', 'in2', 'in3'],
                            [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                             [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
    variables, constraints = shift_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[in0_word_0_class]', x_0)"
    assert "('x[shift_0_18_31]'" in str(variables[-1])
    assert str(constraints[-1]).endswith('== 0')

def test_smt_xor_quasidifferential_propagation_constraints():
    cipher = ShiftCipher(bit_size=2, parameter=1)
    model = SmtXorQuasidifferentialModel(cipher)
    shift_component = cipher.component_from(0, 0)
    variables, constraints = shift_component.smt_xor_quasidifferential_propagation_constraints(model)

    assert variables == ['shift_0_0_0', 'shift_0_0_1', 'qdt_shift_0_0_0', 'qdt_shift_0_0_1']

    assert len(constraints) == 4
    assert constraints[0] == '(assert (not shift_0_0_0))'
    assert constraints[-1] == '(assert (not qdt_plaintext_1))'