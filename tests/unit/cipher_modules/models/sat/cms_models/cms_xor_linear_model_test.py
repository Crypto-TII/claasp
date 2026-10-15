from claasp.cipher_modules.models.sat.cms_models.cms_xor_linear_model import CmsSatXorLinearModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    sat = CmsSatXorLinearModel(speck)
    trail = sat.find_lowest_weight_xor_linear_trail()

    assert trail["total_weight"] == 3.0
