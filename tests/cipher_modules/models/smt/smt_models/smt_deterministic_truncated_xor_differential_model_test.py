from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.smt.smt_models.smt_deterministic_truncated_xor_differential_model import \
        SmtXorDifferentialModel


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    smt = SmtXorDifferentialModel(speck)
    smt.build_deterministic_truncated_xor_differential_trail_model()
    constraints = smt.model_constraints
    assert len(constraints) == 4832
    assert constraints[3] == '(assert (= rot_0_0_3 plaintext_12))'
    assert constraints[4] == '(assert (= rot_0_0_4 plaintext_13))'
    assert constraints[5] == '(assert (= rot_0_0_5 plaintext_14))'
