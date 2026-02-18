import pytest

from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_number_of_active_sboxes_model import (
    MznXorDifferentialNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.name_mappings import INPUT_KEY


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_add_additional_xor_constraints():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables(INPUT_KEY, "not_equal", range(128), (0,) * 128)]
    mzn.build_xor_differential_trail_first_step_model(-1, fixed_variables)
    mzn.add_additional_xor_constraints(5, 1)

    assert len(mzn.list_of_xor_components) == 188
