from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_bitwise_deterministic_truncated_xor_differential_model_arx_optimized \
    import MznBitwiseDeterministicTruncatedXorDifferentialModelARXOptimized


def test_build_bitwise_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    mzn = MznBitwiseDeterministicTruncatedXorDifferentialModelARXOptimized(speck)
    mzn.build_deterministic_truncated_xor_differential_trail_model()
