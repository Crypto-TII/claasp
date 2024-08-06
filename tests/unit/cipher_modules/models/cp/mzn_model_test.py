import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model_arx_optimized import \
        MinizincXorDifferentialModelARXOptimized
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_cipher_model_arx_optimized import MinizincCipherModelARXOptimized
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_deterministic_truncated_xor_differential_model_arx_optimized \
    import MinizincDeterministicTruncatedXorDifferentialModelARXOptimized


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_build_mix_column_truncated_table():
    aes = AESBlockCipher(number_of_rounds=3)
    minizinc = MinizincModel(aes)
    mix_column = aes.component_from(0, 21)
    assert minizinc.build_mix_column_truncated_table(mix_column) == 'array[0..93, 1..8] of int: ' \
                                                              'mix_column_truncated_table_mix_column_0_21 = ' \
                                                              'array2d(0..93, 1..8, [0,0,0,0,0,0,0,0,0,0,0,1,1,' \
                                                              '1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,' \
                                                              '0,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,1,1,' \
                                                              '1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,' \
                                                              '0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,1,0,1,1,' \
                                                              '1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,' \
                                                              '1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,0,' \
                                                              '0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,' \
                                                              '1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,0,0,1,1,1,1,' \
                                                              '0,1,1,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,1,' \
                                                              '1,1,0,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,' \
                                                              '1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,' \
                                                              '1,1,0,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,' \
                                                              '0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,' \
                                                              '1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,' \
                                                              '1,1,0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,' \
                                                              '0,1,0,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,' \
                                                              '1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,' \
                                                              '1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,' \
                                                              '1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,' \
                                                              '1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,' \
                                                              '0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,' \
                                                              '1,0,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,1,1,' \
                                                              '1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,' \
                                                              '1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,' \
                                                              '0,1,0,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,' \
                                                              '1,0,1,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,1,1,1,1,0,' \
                                                              '0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,1,1,1,1,0,' \
                                                              '1,0,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,1,1,1,1,0,' \
                                                              '1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,' \
                                                              '0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,' \
                                                              '1,0,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1]);'


def test_find_possible_number_of_active_sboxes():
    midori = MidoriBlockCipher()
    minizinc = MinizincModel(midori)
    model = minizinc.find_possible_number_of_active_sboxes(9)
    assert model == {3, 4}


def test_fix_variables_value_constraints():

    raiden = RaidenBlockCipher(number_of_rounds=1)
    minizinc = MinizincXorDifferentialModelARXOptimized(raiden)
    minizinc.build_xor_differential_trail_model()
    fixed_variables = [{
        'component_id': 'key',
        'constraint_type': 'equal',
        'bit_positions': [0, 1, 2, 3],
        'bit_values': [0, 1, 0, 1]}]

    constraint_key_y_0 = 'constraint key_y0 = 0;'
    assert minizinc.fix_variables_value_constraints(fixed_variables)[0] == constraint_key_y_0

    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'sum',
                        'bit_positions': [0, 1, 2, 3],
                        'operator': '>',
                        'value': '0'}]

    assert minizinc.fix_variables_value_constraints(fixed_variables)[0] == f'constraint plaintext_y0+plaintext_y1+' \
                                                                           f'plaintext_y2+plaintext_y3>0;'

    raiden = RaidenBlockCipher(number_of_rounds=1)
    minizinc = MinizincDeterministicTruncatedXorDifferentialModelARXOptimized(raiden)
    minizinc.build_deterministic_truncated_xor_differential_trail_model()

    fixed_variables = [{'component_id': 'key',
                       'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [0, 1, 0, 1]}]

    assert minizinc.fix_variables_value_constraints(fixed_variables)[0] == constraint_key_y_0

    raiden = RaidenBlockCipher(number_of_rounds=1)
    minizinc = MinizincCipherModelARXOptimized(raiden)
    minizinc.build_cipher_model()

    fixed_variables = [{'component_id': 'key',
                        'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [0, 1, 0, 1]}]

    assert minizinc.fix_variables_value_constraints(fixed_variables)[0] == constraint_key_y_0


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        minizinc = MinizincModel(speck)
        minizinc.model_constraints()
