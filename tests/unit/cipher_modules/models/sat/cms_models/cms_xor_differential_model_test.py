from claasp.cipher_modules.models.sat.cms_models.cms_xor_differential_model import CmsSatXorDifferentialModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_build_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    cms = CmsSatXorDifferentialModel(speck)
    cms.build_xor_differential_trail_model()

    # Regression check for dispatch inversion: supported components must build constraints
    # rather than falling into "not yet implemented" and leaving an empty model.
    assert len(cms.model_constraints) > 0
    assert len(cms._variables_list) > 0


def test_build_xor_differential_trail_model_with_weight_adds_constraints():
    speck = SpeckBlockCipher(number_of_rounds=2)
    cms_without_weight = CmsSatXorDifferentialModel(speck)
    cms_without_weight.build_xor_differential_trail_model()

    cms_with_weight = CmsSatXorDifferentialModel(speck)
    cms_with_weight.build_xor_differential_trail_model(weight=1)

    assert len(cms_with_weight.model_constraints) > len(cms_without_weight.model_constraints)
    assert len(cms_with_weight._variables_list) >= len(cms_without_weight._variables_list)
