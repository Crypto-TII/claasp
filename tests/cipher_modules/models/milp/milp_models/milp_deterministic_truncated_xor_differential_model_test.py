from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_deterministic_truncated_xor_differential_model import \
    MilpDeterministicTruncatedXorDifferentialModel


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    milp = MilpDeterministicTruncatedXorDifferentialModel(speck)
    milp.init_model_in_sage_milp_class()
    milp.build_deterministic_truncated_xor_differential_trail_model()
    constraints = milp.model_constraints

    assert len(constraints) == 4832
    assert str(constraints[0]) == 'x_16 == x_9'
    assert str(constraints[1]) == 'x_17 == x_10'
    assert str(constraints[4830]) == 'x_4190 == x_4158'
    assert str(constraints[4831]) == 'x_4191 == x_4159'
