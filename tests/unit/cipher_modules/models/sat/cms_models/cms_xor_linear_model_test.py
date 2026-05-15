from claasp.cipher_modules.models.sat.cms_models.cms_xor_linear_model import CmsSatXorLinearModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_build_xor_linear_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    cms = CmsSatXorLinearModel(speck)
    cms.build_xor_linear_trail_model()
