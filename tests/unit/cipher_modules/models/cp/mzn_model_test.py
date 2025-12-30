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
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from minizinc import Model, Solver, Instance, Status


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

def test_build_generic_cp_model_from_dictionary():

    speck = SpeckBlockCipher(number_of_rounds=3)
    model = MznXorDifferentialModelARXOptimized(speck)
    component_and_model_types = []

    for component in speck.get_all_components():
        component_and_model_types.append({
            "component_object": component,
            "model_type": "minizinc_xor_differential_propagation_constraints"
        })

    model.build_generic_cp_model_from_dictionary(component_and_model_types)

    #Caso especial para ARX
    model.init_constraints()

    fixed_variables = []

    fixed_variables.append(
        set_fixed_variables(
            component_id="plaintext",
            constraint_type="equal",
            bit_positions=list(range(32)),
            bit_values=integer_to_bit_list(0x00400000, 32, 'big')
        )
    )

    fixed_variables.append(
        set_fixed_variables(
            component_id="key",
            constraint_type="equal",
            bit_positions=list(range(64)),
            bit_values=[0] * 64
        )
    )

    fixed_variables.append(
        set_fixed_variables(
            component_id="cipher_output_2_12",
            constraint_type="equal",
            bit_positions=list(range(32)),
            bit_values=integer_to_bit_list(0x8000840a, 32, 'big')
        )
    )

    constraints = model.fix_variables_value_constraints_for_ARX(fixed_variables)

    result = model.solve_for_ARX(solver_name="cp-sat")

    assert result.status in {
        Status.SATISFIED,
        Status.OPTIMAL_SOLUTION,
        Status.ALL_SOLUTIONS,
    }
