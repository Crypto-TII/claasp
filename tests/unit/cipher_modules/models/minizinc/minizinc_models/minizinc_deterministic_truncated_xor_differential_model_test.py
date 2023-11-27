from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_deterministic_truncated_xor_differential_model \
    import MinizincDeterministicTruncatedXorDifferentialModel


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    minizinc = MinizincDeterministicTruncatedXorDifferentialModel(speck)
    minizinc.build_deterministic_truncated_xor_differential_trail_model()
