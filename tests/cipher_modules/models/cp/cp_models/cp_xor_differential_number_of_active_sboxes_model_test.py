import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_number_of_active_sboxes_model import \
    CpXorDifferentialNumberOfActiveSboxesModel, build_xor_truncated_table
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_add_additional_xor_constraints():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpXorDifferentialNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables('key', 'not_equal', range(128), integer_to_bit_list(0, 128, 'little'))]
    cp.build_xor_differential_trail_first_step_model(-1, fixed_variables)
    cp.add_additional_xor_constraints(5, 1)

    assert len(cp.list_of_xor_components) == 188
