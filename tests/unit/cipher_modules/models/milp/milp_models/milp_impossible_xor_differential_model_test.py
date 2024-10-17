from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_impossible_xor_differential_model import \
        MilpImpossibleXorDifferentialModel
from claasp.name_mappings import IMPOSSIBLE_XOR_DIFFERENTIAL, INPUT_KEY, INPUT_PLAINTEXT


def test_find_one_impossible_xor_differential_trail():
    lblock = LBlockBlockCipher(number_of_rounds=16)
    milp = MilpImpossibleXorDifferentialModel(lblock)
    trail = milp.find_one_impossible_xor_differential_trail(0, 0, 0)

    assert str(trail['cipher']) == 'lblock_p64_k80_o64_r16'
    assert trail['model_type'] == IMPOSSIBLE_XOR_DIFFERENTIAL
    assert trail['solver_name'] == 'GLPK'
    assert trail['components_values'] == []


def test_find_all_impossible_xor_differential_trails():
    lblock = LBlockBlockCipher(number_of_rounds=16)
    milp = MilpImpossibleXorDifferentialModel(lblock)
    trails = milp.find_all_impossible_xor_differential_trails(0, 0, 0)

    assert len(trails) == 0