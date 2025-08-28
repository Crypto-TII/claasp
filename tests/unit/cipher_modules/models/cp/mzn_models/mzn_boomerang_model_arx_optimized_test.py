import os
import numpy as np

from claasp.cipher_modules.models.cp.mzn_models.mzn_boomerang_model_arx_optimized import MznBoomerangModelARXOptimized
from claasp.cipher_modules.models.cp.solvers import XOR
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.name_mappings import BOOMERANG_XOR_DIFFERENTIAL


SPECK32_64_WORD_SIZE = 16
SPECK32_64_ALPHA = 7
SPECK32_64_BETA = 2
MASK_VAL = 2 ** SPECK32_64_WORD_SIZE - 1


def speck32_64_rol(x, k):
    return ((x << k) & MASK_VAL) | (x >> (SPECK32_64_WORD_SIZE - k))


def speck32_64_ror(x, k):
    return (x >> k) | ((x << (SPECK32_64_WORD_SIZE - k)) & MASK_VAL)


def speck32_64_decrypt(ciphertext, ks):
    def dec_one_round(c, subkey_):
        c0, c1 = c
        c1 = c1 ^ c0
        c1 = speck32_64_ror(c1, SPECK32_64_BETA)
        c0 = c0 ^ subkey_
        c0 = (c0 - c1) & MASK_VAL
        c0 = speck32_64_rol(c0, SPECK32_64_ALPHA)
        return c0, c1

    x, y = ciphertext
    for subkey in reversed(ks):
        x, y = dec_one_round((x, y), subkey)
    return x, y


def speck32_64_enc_one_round(plaintext, subkey):
    c0, c1 = plaintext
    c0 = speck32_64_ror(c0, SPECK32_64_ALPHA)
    c0 = (c0 + c1) & MASK_VAL
    c0 = c0 ^ subkey
    c1 = speck32_64_rol(c1, SPECK32_64_BETA)
    c1 = c1 ^ c0
    return c0, c1


def speck32_64_expand_key(k, t):
    ks = [0] * t
    ks[0] = k[-1]
    left_word = list(reversed(k[:-1]))
    for i in range(t - 1):
        left_word[i % len(left_word)], ks[i + 1] = speck32_64_enc_one_round((left_word[i % len(left_word)], ks[i]), i)
    return ks


def speck32_64_encrypt(p, ks):
    x, y = p
    for k in ks:
        x, y = speck32_64_enc_one_round((x, y), k)
    return x, y


def speck32_64_bct_distinguisher_verifier(delta_, nabla_, nr, n=2**10):
    keys = np.frombuffer(os.urandom(8 * n), dtype=np.uint16).reshape(4, -1)
    plaintext_data_0_left = np.frombuffer(os.urandom(2 * n), dtype=np.uint16)
    plaintext_data_0_right = np.frombuffer(os.urandom(2 * n), dtype=np.uint16)
    plaintext_data_1_left = plaintext_data_0_left ^ delta_[0]
    plaintext_data_1_right = plaintext_data_0_right ^ delta_[1]
    subkey_list = speck32_64_expand_key(keys, nr)

    ciphertext_data_0_left, ciphertext_data_0_right = speck32_64_encrypt(
        (plaintext_data_0_left, plaintext_data_0_right), subkey_list
    )
    ciphertext_data_1_left, ciphertext_data_1_right = speck32_64_encrypt(
        (plaintext_data_1_left, plaintext_data_1_right), subkey_list
    )

    output_xor_nabla_0 = (ciphertext_data_0_left ^ nabla_[0], ciphertext_data_0_right ^ nabla_[1])
    output_xor_nabla_1 = (ciphertext_data_1_left ^ nabla_[0], ciphertext_data_1_right ^ nabla_[1])
    plaintext_data_2_left, plaintext_data_2_right = speck32_64_decrypt(output_xor_nabla_0, subkey_list)
    plaintext_data_3_left, plaintext_data_3_right = speck32_64_decrypt(output_xor_nabla_1, subkey_list)

    nabla_temp = (np.uint32(delta_[0]) << 16) ^ delta_[1]
    nabla_prime_temp_left = np.uint32(plaintext_data_2_left ^ plaintext_data_3_left) << 16
    nabla_prime_temp = nabla_prime_temp_left ^ (plaintext_data_2_right ^ plaintext_data_3_right)

    total = np.sum(nabla_temp == nabla_prime_temp)
    return total / n


def split_32bit_to_16bit(difference):
    lower_16 = difference & 0xFFFF
    upper_16 = (difference >> 16) & 0xFFFF
    return upper_16, lower_16


def test_build_boomerang_model_speck_single_key():
    speck = SpeckBlockCipher(number_of_rounds=8)
    speck = speck.remove_key_schedule()

    top_cipher_end = ["xor_3_10", "rot_4_6"]

    bottom_cipher_start = ["xor_4_8", "rot_4_9", "key_4_2", "key_5_2", "key_6_2", "key_7_2"]

    sboxes = ["modadd_4_7"]

    mzn_bct_model = MznBoomerangModelARXOptimized(speck, top_cipher_end, bottom_cipher_start, sboxes)

    fixed_variables_for_top_cipher = [
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "key_0_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_1_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_2_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_3_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "xor_3_10",
            "constraint_type": "sum",
            "bit_positions": list(range(16)),
            "operator": ">",
            "value": "0",
        },
    ]

    fixed_variables_for_bottom_cipher = [
        {
            "component_id": "new_xor_3_10",
            "constraint_type": "sum",
            "bit_positions": list(range(16)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "key_4_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_5_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_6_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
        {
            "component_id": "key_7_2",
            "constraint_type": "equal",
            "bit_positions": list(range(16)),
            "bit_values": (0,) * 16,
        },
    ]

    mzn_bct_model.create_boomerang_model(fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher)
    result = mzn_bct_model.solve_for_ARX(solver_name=XOR)
    total_weight = MznBoomerangModelARXOptimized._get_total_weight(result)
    parsed_result = mzn_bct_model.bct_parse_result(result, XOR, total_weight, BOOMERANG_XOR_DIFFERENTIAL)
    filename = "."
    mzn_bct_model.write_minizinc_model_to_file(filename)

    assert os.path.exists(mzn_bct_model.filename), "File was not created"
    os.remove(mzn_bct_model.filename)
    assert total_weight == parsed_result["total_weight"]
    input_difference = split_32bit_to_16bit(int(parsed_result["component_values"]["plaintext"]["value"], 16))
    output_difference = split_32bit_to_16bit(int(parsed_result["component_values"]["cipher_output_7_12"]["value"], 16))
    assert (
        speck32_64_bct_distinguisher_verifier(input_difference, output_difference, speck.number_of_rounds, n=2**20)
        > 0.0001
    )


def test_build_boomerang_model_chacha():
    chacha = ChachaPermutation(number_of_rounds=8)
    top_cipher_end = [
        "modadd_3_0",
        "rot_3_5",
        "modadd_3_3",
        "rot_3_2",
        "modadd_3_6",
        "rot_3_11",
        "modadd_3_9",
        "rot_3_8",
        "modadd_3_12",
        "rot_3_17",
        "modadd_3_15",
        "rot_3_14",
        "modadd_3_18",
        "rot_3_23",
        "modadd_3_21",
        "rot_3_20",
    ]

    bottom_cipher_start = [
        "xor_4_4",
        "modadd_4_3",
        "xor_4_1",
        "xor_4_10",
        "modadd_4_9",
        "xor_4_7",
        "xor_4_16",
        "modadd_4_15",
        "xor_4_13",
        "xor_4_22",
        "modadd_4_21",
        "xor_4_19",
    ]

    sboxes = ["modadd_4_0", "modadd_4_6", "modadd_4_12", "modadd_4_18"]
    mzn_bct_model = MznBoomerangModelARXOptimized(chacha, top_cipher_end, bottom_cipher_start, sboxes)

    fixed_variables_for_top_cipher = [
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": list(range(512)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": list(range(384)),
            "operator": "=",
            "value": "0",
        },
    ]

    fixed_variables_for_bottom_cipher = [
        {
            "component_id": "new_rot_3_23",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "new_rot_3_5",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "new_rot_3_11",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
        {
            "component_id": "new_rot_3_17",
            "constraint_type": "sum",
            "bit_positions": list(range(32)),
            "operator": ">",
            "value": "0",
        },
    ]

    mzn_bct_model.create_boomerang_model(fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher)
    result = mzn_bct_model.solve_for_ARX(solver_name=XOR)
    total_weight = MznBoomerangModelARXOptimized._get_total_weight(result)
    parsed_result = mzn_bct_model.bct_parse_result(result, XOR, total_weight, BOOMERANG_XOR_DIFFERENTIAL)
    filename = "."
    mzn_bct_model.write_minizinc_model_to_file(filename)

    assert os.path.exists(mzn_bct_model.filename), "File was not created"

    os.remove(mzn_bct_model.filename)

    assert total_weight == parsed_result["total_weight"]
