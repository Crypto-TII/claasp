from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_impossible_xor_differential_model import \
        SatImpossibleXorDifferentialModel
from claasp.name_mappings import IMPOSSIBLE_XOR_DIFFERENTIAL, INPUT_KEY, INPUT_PLAINTEXT


def test_find_one_impossible_xor_differential_trail():
    lblock = LBlockBlockCipher(number_of_rounds=16)
    sat = SatImpossibleXorDifferentialModel(lblock)
    trail = sat.find_one_impossible_xor_differential_trail(1, 0, 0)

    assert str(trail['cipher']) == 'lblock_p64_k80_o64_r16'
    assert trail['model_type'] == IMPOSSIBLE_XOR_DIFFERENTIAL
    assert trail['solver_name'] == 'CRYPTOMINISAT_EXT'
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values'][INPUT_KEY]['value'][:-3] == '00000000000000000'
    assert trail['components_values'][INPUT_PLAINTEXT]['value'] == '0000000000000000'
    assert trail['components_values']['cipher_output_15_19']['value'] == '0000000000000000'


def test_find_all_impossible_xor_differential_trails():
    lblock = LBlockBlockCipher(number_of_rounds=16)
    sat = SatImpossibleXorDifferentialModel(lblock)
    trails = sat.find_all_impossible_xor_differential_trails(1, 0, 0)

    assert len(trails) == 4