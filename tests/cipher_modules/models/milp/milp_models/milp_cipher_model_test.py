from claasp.cipher_modules.models.milp.milp_models.milp_cipher_model import MilpCipherModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_build_cipher_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    milp = MilpCipherModel(speck)
    milp.init_model_in_sage_milp_class()
    milp.build_cipher_model()
    constraints = milp.model_constraints

    assert len(constraints) == 9296
    assert str(constraints[0]) == 'x_16 == x_9'
    assert str(constraints[1]) == 'x_17 == x_10'
    assert str(constraints[9294]) == 'x_4926 == x_4878'
    assert str(constraints[9295]) == 'x_4927 == x_4879'
