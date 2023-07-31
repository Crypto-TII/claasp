from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_deterministic_truncated_xor_differential_model import \
    SatDeterministicTruncatedXorDifferentialModel


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    sat = SatDeterministicTruncatedXorDifferentialModel(speck)
    sat.build_deterministic_truncated_xor_differential_trail_model()
