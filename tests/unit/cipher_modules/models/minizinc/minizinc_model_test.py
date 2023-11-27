import pytest

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import \
        MinizincXorDifferentialModel
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_cipher_model import MinizincCipherModel
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_deterministic_truncated_xor_differential_model \
    import MinizincDeterministicTruncatedXorDifferentialModel


def test_fix_variables_value_constraints():

    raiden = RaidenBlockCipher(number_of_rounds=1)
    minizinc = MinizincXorDifferentialModel(raiden)
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
    minizinc = MinizincDeterministicTruncatedXorDifferentialModel(raiden)
    minizinc.build_deterministic_truncated_xor_differential_trail_model()

    fixed_variables = [{'component_id': 'key',
                       'constraint_type': 'equal',
                        'bit_positions': [0, 1, 2, 3],
                        'bit_values': [0, 1, 0, 1]}]

    assert minizinc.fix_variables_value_constraints(fixed_variables)[0] == constraint_key_y_0

    raiden = RaidenBlockCipher(number_of_rounds=1)
    minizinc = MinizincCipherModel(raiden)
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
