from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_cipher_model_arx_optimized import MznCipherModelARXOptimized


def test_build_cipher_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    mzn = MznCipherModelARXOptimized(speck)
    mzn.build_cipher_model()
