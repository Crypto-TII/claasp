from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_cipher_model_arx_optimized import MinizincCipherModelARXOptimized


def test_build_cipher_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    minizinc = MinizincCipherModelARXOptimized(speck)
    minizinc.build_cipher_model()
