from claasp.cipher_modules.models.cp.mzn_models.mzn_deterministic_truncated_xor_differential_model_arx_optimized import (
    MznDeterministicTruncatedXorDifferentialModelARXOptimized,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    mzn = MznDeterministicTruncatedXorDifferentialModelARXOptimized(speck)
    mzn.build_deterministic_truncated_xor_differential_trail_model()
