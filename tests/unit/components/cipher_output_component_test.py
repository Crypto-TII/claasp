from claasp.components.cipher_output_component import CipherOutput
from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)
from claasp.ciphers.block_ciphers.rectangle_block_cipher import RectangleBlockCipher

def test_cp_constraints():
    output_component = CipherOutput(
        2,
        12,
        ["xor_2_8", "xor_2_10"],
        [list(range(16)), list(range(16))],
        32,
    )
    declarations, constraints = output_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint cipher_output_2_12[0] = xor_2_8[0];'
    assert constraints[1] == 'constraint cipher_output_2_12[1] = xor_2_8[1];'
    assert constraints[-1] == 'constraint cipher_output_2_12[31] = xor_2_10[15];'


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    class DummyModel:
        word_size = 4

    output_component = CipherOutput(
        0,
        35,
        ["xor_0_31", "xor_0_32", "xor_0_33", "xor_0_34"],
        [list(range(16)), list(range(16)), list(range(16)), list(range(16))],
        64,
        is_intermediate=True,
        output_tag="intermediate_output",
    )
    cp = DummyModel()
    declarations, constraints = output_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint intermediate_output_0_35_value[0] = xor_0_31_value[0];'
    assert constraints[-1] == 'constraint intermediate_output_0_35_active[15] = xor_0_34_active[3];'

def test_smt_xor_quasidifferential_propagation_constraints():
    cipher = RectangleBlockCipher(number_of_rounds=1)
    model = SmtXorQuasidifferentialModel(cipher)
    cipher_output = cipher.component_from_id('cipher_output_0_33')
    variables, constraints = cipher_output.smt_xor_quasidifferential_propagation_constraints(model)

    assert len(variables) == 128
    assert variables[0] == 'cipher_output_0_33_0'
    assert variables[-1] == 'qdt_cipher_output_0_33_63'

    assert len(constraints) == 128
    assert constraints[0] == '(assert (= cipher_output_0_33_0 xor_0_30_0))'
    assert constraints[-1] == '(assert (= qdt_cipher_output_0_33_63 qdt_xor_0_30_63))'