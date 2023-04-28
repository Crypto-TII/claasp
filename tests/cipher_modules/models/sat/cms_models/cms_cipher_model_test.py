from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.cms_models.cms_cipher_model import CmsSatCipherModel


def test_build_cipher_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    cms = CmsSatCipherModel(speck)
    cms.build_cipher_model()
