from claasp.components.constant_component import Constant
from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)
from claasp.ciphers.block_ciphers.rectangle_block_cipher import RectangleBlockCipher

def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    class DummyModel:
        word_size = 8

    constant_component = Constant(0, 18, 16, 0xAB01)
    declarations, constraints = constant_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())

    assert declarations == ['array[0..1] of var 0..1: constant_0_18_active = array1d(0..1, [0,0]);',
                            'array[0..1] of var 0..1: constant_0_18_value = array1d(0..1, [0,0]);']

    assert constraints == []


def test_cp_xor_linear_mask_propagation_constraints():
    constant_component = Constant(2, 0, 16, 0x0000)
    declarations, constraints = constant_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..15] of var 0..1: constant_2_0_o;']

    assert constraints == []


def test_smt_constraints():
    constant_component = Constant(0, 2, 32, 0x9d9eec79)
    output_bit_ids, constraints = constant_component.smt_constraints()

    assert output_bit_ids[0] == 'constant_0_2_0'
    assert output_bit_ids[1] == 'constant_0_2_1'
    assert output_bit_ids[-2] == 'constant_0_2_30'
    assert output_bit_ids[-1] == 'constant_0_2_31'

    assert constraints[0] == '(assert constant_0_2_0)'
    assert constraints[1] == '(assert (not constant_0_2_1))'
    assert constraints[-2] == '(assert (not constant_0_2_30))'
    assert constraints[-1] == '(assert constant_0_2_31)'


def test_smt_xor_differential_propagation_constraints():
    constant_component = Constant(0, 2, 32, 0x00000000)
    output_bit_ids, constraints = constant_component.smt_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'constant_0_2_0'
    assert output_bit_ids[1] == 'constant_0_2_1'
    assert output_bit_ids[-2] == 'constant_0_2_30'
    assert output_bit_ids[-1] == 'constant_0_2_31'

    assert constraints[0] == '(assert (not constant_0_2_0))'
    assert constraints[1] == '(assert (not constant_0_2_1))'
    assert constraints[-2] == '(assert (not constant_0_2_30))'
    assert constraints[-1] == '(assert (not constant_0_2_31))'


def test_smt_xor_linear_mask_propagation_constraints():
    constant_component = Constant(0, 2, 32, 0xDEADBEEF)
    output_bit_ids, constraints = constant_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'constant_0_2_0_o'
    assert output_bit_ids[1] == 'constant_0_2_1_o'
    assert output_bit_ids[-2] == 'constant_0_2_30_o'
    assert output_bit_ids[-1] == 'constant_0_2_31_o'

    assert constraints == []

def test_smt_xor_quasidifferential_propagation_constraints():
    cipher = RectangleBlockCipher(number_of_rounds=1)
    model = SmtXorQuasidifferentialModel(cipher)
    constant_component = cipher.component_from_id('constant_0_26')
    variables, constraints = constant_component.smt_xor_quasidifferential_propagation_constraints(model)

    assert len(variables) == 10
    assert variables[0] == 'constant_0_26_0'
    assert variables[-1] == 'qdt_constant_0_26_4'

    assert len(constraints) == 5
    assert constraints[0] == '(assert (not constant_0_26_0))'
    assert constraints[-1] == '(assert (not constant_0_26_4))'