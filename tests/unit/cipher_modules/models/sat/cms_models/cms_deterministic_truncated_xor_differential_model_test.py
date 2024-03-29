from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.cms_models.cms_bitwise_deterministic_truncated_xor_differential_model import \
    CmsSatDeterministicTruncatedXorDifferentialModel


def test_build_bitwise_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(number_of_rounds=22)
    cms = CmsSatDeterministicTruncatedXorDifferentialModel(speck)
    cms.build_bitwise_deterministic_truncated_xor_differential_trail_model()
