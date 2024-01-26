from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_boomerang_model import MinizincBoomerangModel
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.name_mappings import BOOMERANG_XOR_DIFFERENTIAL


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
        "rot_3_20"
    ]

    bottom_cipher_start = [
        #"modadd_4_0",
        "xor_4_4",
        "modadd_4_3",
        "xor_4_1",

        #"modadd_4_6",
        "xor_4_10",
        "modadd_4_9",
        "xor_4_7",

        #"modadd_4_12",
        "xor_4_16",
        "modadd_4_15",
        "xor_4_13",

        #"modadd_4_18",
        "xor_4_22",
        "modadd_4_21",
        "xor_4_19"
    ]

    sboxes = [
        "modadd_4_0",
        "modadd_4_6",
        "modadd_4_12",
        "modadd_4_18"
    ]
    minizinc_bct_model = MinizincBoomerangModel(chacha, top_cipher_end, bottom_cipher_start, sboxes)

    fixed_variables_for_top_cipher = [
        {'component_id': 'plaintext', 'constraint_type': 'sum', 'bit_positions': [i for i in range(512)],
         'operator': '>', 'value': '0'},
        {'component_id': 'plaintext', 'constraint_type': 'sum', 'bit_positions': [i for i in range(384)],
         'operator': '=', 'value': '0'}
    ]

    fixed_variables_for_bottom_cipher = [
        {'component_id': 'new_rot_3_23', 'constraint_type': 'sum', 'bit_positions': [i for i in range(32)],
         'operator': '>', 'value': '0'},
        {'component_id': 'new_rot_3_5', 'constraint_type': 'sum', 'bit_positions': [i for i in range(32)],
         'operator': '>', 'value': '0'},
        {'component_id': 'new_rot_3_11', 'constraint_type': 'sum', 'bit_positions': [i for i in range(32)],
         'operator': '>', 'value': '0'},
        {'component_id': 'new_rot_3_17', 'constraint_type': 'sum', 'bit_positions': [i for i in range(32)],
         'operator': '>', 'value': '0'}]

    minizinc_bct_model.create_boomerang_model(fixed_variables_for_top_cipher, fixed_variables_for_bottom_cipher)
    result = minizinc_bct_model.solve(solver_name='Xor')
    total_weight = MinizincBoomerangModel._get_total_weight(result)
    parsed_result = minizinc_bct_model.bct_parse_result(result, 'Xor', total_weight, BOOMERANG_XOR_DIFFERENTIAL)
    filename = '.'
    minizinc_bct_model.write_minizinc_model_to_file(filename)
    import os
    assert os.path.exists(minizinc_bct_model.filename), "File was not created"
    os.remove(minizinc_bct_model.filename)
    assert total_weight == parsed_result['total_weight']

