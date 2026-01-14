import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import \
        MznXorDifferentialModelARXOptimized
from claasp.cipher_modules.models.cp.mzn_models.mzn_cipher_model_arx_optimized import MznCipherModelARXOptimized
from claasp.cipher_modules.models.cp.mzn_models.mzn_deterministic_truncated_xor_differential_model_arx_optimized \
    import MznDeterministicTruncatedXorDifferentialModelARXOptimized


def test_solver_names():
    speck = SpeckBlockCipher(number_of_rounds=3)
    mzn = MznModel(speck)
    solver_names = mzn.solver_names()
    assert isinstance(solver_names, list)
    assert len(solver_names) > 0
    # Check that each entry has the required keys
    for solver in solver_names:
        assert 'solver_brand_name' in solver
        assert 'solver_name' in solver
        assert 'keywords' not in solver  # verbose=False by default
    
    # Test verbose mode
    verbose_solver_names = mzn.solver_names(verbose=True)
    assert isinstance(verbose_solver_names, list)
    # External solvers should have keywords when verbose=True
    external_solvers = [s for s in verbose_solver_names if 'keywords' in s]
    assert len(external_solvers) > 0


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_build_mix_column_truncated_table():
    aes = AESBlockCipher(number_of_rounds=3)
    mzn = MznModel(aes)
    mix_column = aes.component_from(0, 21)
    assert mzn.build_mix_column_truncated_table(mix_column) == 'array[0..93, 1..8] of int: ' \
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
    mzn = MznModel(midori)
    model = mzn.find_possible_number_of_active_sboxes(9)
    assert model == {3, 4}


def test_fix_variables_value_constraints():

    raiden = RaidenBlockCipher(number_of_rounds=1)
    mzn = MznXorDifferentialModelARXOptimized(raiden)
    mzn.build_xor_differential_trail_model()
    fixed_variables = [{
        'component_id': 'key',
        'constraint_type': 'equal',
        'bit_positions': [0, 1, 2, 3],
        'bit_values': [0, 1, 0, 1]}]

    constraint_key_y_0 = 'constraint key_y0 = 0;'
    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == constraint_key_y_0

    fixed_variables = [{'component_id': 'plaintext',
                        'constraint_type': 'sum',
                        'bit_positions': [0, 1, 2, 3],
                        'operator': '>',
                        'value': '0'}]

    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == f'constraint plaintext_y0+plaintext_y1+' \
                                                                           f'plaintext_y2+plaintext_y3>0;'

    raiden = RaidenBlockCipher(number_of_rounds=1)
    mzn = MznDeterministicTruncatedXorDifferentialModelARXOptimized(raiden)
    mzn.build_deterministic_truncated_xor_differential_trail_model()

    fixed_variables = [{'component_id': 'key',
                       'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [0, 1, 0, 1]}]

    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == constraint_key_y_0

    raiden = RaidenBlockCipher(number_of_rounds=1)
    mzn = MznCipherModelARXOptimized(raiden)
    mzn.build_cipher_model()

    fixed_variables = [{'component_id': 'key',
                        'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [0, 1, 0, 1]}]

    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == constraint_key_y_0


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        mzn = MznModel(speck)
        mzn.model_constraints()
