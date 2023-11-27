from claasp.components.constant_component import Constant
from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = CpModel(aes)
    constant_component = Constant(0, 18, 16, 0xAB01)
    declarations, constraints = constant_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)

    assert declarations == ['array[0..1] of var 0..1: constant_0_18_active = array1d(0..1, [0,0]);',
                            'array[0..1] of var 0..1: constant_0_18_value = array1d(0..1, [0,0]);']

    assert constraints == []


def test_cp_xor_linear_mask_propagation_constraints():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
    constant_component = speck.component_from(2, 0)
    declarations, constraints = constant_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..15] of var 0..1: constant_2_0_o;']

    assert constraints == []


def test_smt_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    constant_component = tea.component_from(0, 2)
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
    tea = TeaBlockCipher(number_of_rounds=3)
    constant_component = tea.component_from(0, 2)
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
    tea = TeaBlockCipher(number_of_rounds=3)
    constant_component = tea.component_from(0, 2)
    output_bit_ids, constraints = constant_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'constant_0_2_0_o'
    assert output_bit_ids[1] == 'constant_0_2_1_o'
    assert output_bit_ids[-2] == 'constant_0_2_30_o'
    assert output_bit_ids[-1] == 'constant_0_2_31_o'

    assert constraints == []
