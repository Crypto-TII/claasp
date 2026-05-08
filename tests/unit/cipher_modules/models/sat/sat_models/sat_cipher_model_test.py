from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY


def test_find_missing_bits():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
    sat = SatCipherModel(speck)
    cipher_output_id = speck.get_all_components_ids()[-1]
    plaintext_bits = integer_to_bit_list(0x6574694C, 32, "big")
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="equal", bit_positions=range(32), bit_values=plaintext_bits
    )
    key_bits = integer_to_bit_list(0x1918111009080100, 64, "big")
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=key_bits
    )

    missing_bits = sat.find_missing_bits(fixed_values=[plaintext, key])

    assert missing_bits["components_values"][cipher_output_id]["value"] == "0xa86842f2"
