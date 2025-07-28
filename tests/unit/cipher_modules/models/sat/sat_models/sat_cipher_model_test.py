from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel


def test_find_missing_bits():
    speck = SpeckBlockCipher(number_of_rounds=22)
    cipher_output_id = speck.get_all_components_ids()[-1]
    sat = SatCipherModel(speck)
    ciphertext = set_fixed_variables(
        component_id=cipher_output_id,
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x1234ABCD, 32, "big"),
    )

    missing_bits = sat.find_missing_bits(fixed_values=[ciphertext])

    assert str(missing_bits["cipher"]) == "speck_p32_k64_o32_r22"
    assert missing_bits["model_type"] == "cipher"
    assert missing_bits["components_values"][cipher_output_id] == {"value": "0x1234abcd"}
    assert missing_bits["status"] == "SATISFIABLE"
