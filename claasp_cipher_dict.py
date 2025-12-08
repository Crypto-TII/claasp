data_str = '''
{
'cipher_id': 'speck_partial_0_to_4_p32_k64_o32_r0',
'cipher_type': 'block_cipher',
'cipher_inputs': ['upper_plaintext', 'upper_key', 'upper_xor_1_5', 'upper_xor_2_5', 'upper_xor_3_5', 'upper_xor_4_5', 'lower_cipher_output_8_12', 'lower_key', 'lower_xor_8_5', 'lower_xor_7_5', 'lower_xor_6_5', 'lower_xor_5_5', 'lower_xor_4_5'],
'cipher_inputs_bit_size': [32, 64, 16, 16, 16, 16, 32, 64, 16, 16, 16, 16, 16],
'cipher_output_bit_size': 32,
'cipher_number_of_rounds': 9,
'cipher_rounds' : [
  # round 0
  [
  {
    # round = 0 - round component = 0
    'id': 'upper_rot_0_0',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_plaintext'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 7],
  },
  {
    # round = 0 - round component = 1
    'id': 'upper_modadd_0_1',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_rot_0_0', 'upper_plaintext'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
    'output_bit_size': 16,
    'description': ['MODADD', 2, None],
  },
  {
    # round = 0 - round component = 2
    'id': 'upper_xor_0_2',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_modadd_0_1', 'upper_key'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 0 - round component = 3
    'id': 'upper_rot_0_3',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_plaintext'],
    'input_bit_positions': [[16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
    'output_bit_size': 16,
    'description': ['ROTATE', -2],
  },
  {
    # round = 0 - round component = 4
    'id': 'upper_xor_0_4',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_0_2', 'upper_rot_0_3'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 0 - round component = 5
    'id': 'upper_intermediate_output_0_6',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_0_2', 'upper_xor_0_4'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 1
  [
  {
    # round = 1 - round component = 0
    'id': 'upper_rot_1_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_0_2'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 7],
  },
  {
    # round = 1 - round component = 1
    'id': 'upper_modadd_1_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_rot_1_6', 'upper_xor_0_4'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODADD', 2, None],
  },
  {
    # round = 1 - round component = 2
    'id': 'upper_xor_1_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_modadd_1_7', 'upper_xor_1_5'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 1 - round component = 3
    'id': 'upper_rot_1_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_0_4'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -2],
  },
  {
    # round = 1 - round component = 4
    'id': 'upper_xor_1_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_1_8', 'upper_rot_1_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 1 - round component = 5
    'id': 'upper_intermediate_output_1_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_1_8', 'upper_xor_1_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 2
  [
  {
    # round = 2 - round component = 0
    'id': 'upper_rot_2_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_1_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 7],
  },
  {
    # round = 2 - round component = 1
    'id': 'upper_modadd_2_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_rot_2_6', 'upper_xor_1_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODADD', 2, None],
  },
  {
    # round = 2 - round component = 2
    'id': 'upper_xor_2_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_modadd_2_7', 'upper_xor_2_5'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 2 - round component = 3
    'id': 'upper_rot_2_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_1_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -2],
  },
  {
    # round = 2 - round component = 4
    'id': 'upper_xor_2_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_2_8', 'upper_rot_2_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 2 - round component = 5
    'id': 'upper_intermediate_output_2_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_2_8', 'upper_xor_2_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 3
  [
  {
    # round = 3 - round component = 0
    'id': 'upper_rot_3_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_2_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 7],
  },
  {
    # round = 3 - round component = 1
    'id': 'upper_modadd_3_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_rot_3_6', 'upper_xor_2_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODADD', 2, None],
  },
  {
    # round = 3 - round component = 2
    'id': 'upper_xor_3_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_modadd_3_7', 'upper_xor_3_5'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 3 - round component = 3
    'id': 'upper_rot_3_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_2_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -2],
  },
  {
    # round = 3 - round component = 4
    'id': 'upper_xor_3_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_3_8', 'upper_rot_3_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 3 - round component = 5
    'id': 'upper_intermediate_output_3_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_3_8', 'upper_xor_3_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 4
  [
  {
    # round = 4 - round component = 0
    'id': 'upper_rot_4_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_3_8'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 7],
  },
  {
    # round = 4 - round component = 1
    'id': 'upper_modadd_4_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_rot_4_6', 'upper_xor_3_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODADD', 2, None],
  },
  {
    # round = 4 - round component = 2
    'id': 'upper_xor_4_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_modadd_4_7', 'upper_xor_4_5'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 4 - round component = 3
    'id': 'upper_rot_4_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['upper_xor_3_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -2],
  },
  {
    # round = 4 - round component = 4
    'id': 'upper_xor_4_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_4_8', 'upper_rot_4_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 4 - round component = 5
    'id': 'upper_intermediate_output_4_12',
    'type': 'cipher_output',
    'input_bit_size': 32,
    'input_id_link': ['upper_xor_4_8', 'upper_xor_4_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['cipher_output'],
  },
  {
    # round = 4 - round component = 6
    'id': 'lower_xor_4_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_4_5', 'lower_rot_5_6'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 4 - round component = 7
    'id': 'lower_xor_4_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_5_6', 'lower_rot_5_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 4 - round component = 8
    'id': 'lower_rot_4_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_xor_4_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 2],
  },
  {
    # round = 4 - round component = 9
    'id': 'lower_modadd_4_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_4_8', 'lower_rot_4_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODSUB', 2, None],
  },
  {
    # round = 4 - round component = 10
    'id': 'lower_rot_4_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_modadd_4_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -7],
  },
  {
    # round = 4 - round component = 11
    'id': 'lower_intermediate_output_4_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_5_6', 'lower_rot_5_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 5
  [
  {
    # round = 5 - round component = 0
    'id': 'lower_xor_5_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_5_5', 'lower_rot_6_6'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 5 - round component = 1
    'id': 'lower_xor_5_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_6_6', 'lower_rot_6_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 5 - round component = 2
    'id': 'lower_rot_5_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_xor_5_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 2],
  },
  {
    # round = 5 - round component = 3
    'id': 'lower_modadd_5_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_5_8', 'lower_rot_5_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODSUB', 2, None],
  },
  {
    # round = 5 - round component = 4
    'id': 'lower_rot_5_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_modadd_5_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -7],
  },
  {
    # round = 5 - round component = 5
    'id': 'lower_intermediate_output_5_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_6_6', 'lower_rot_6_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 6
  [
  {
    # round = 6 - round component = 0
    'id': 'lower_xor_6_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_6_5', 'lower_rot_7_6'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 6 - round component = 1
    'id': 'lower_xor_6_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_7_6', 'lower_rot_7_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 6 - round component = 2
    'id': 'lower_rot_6_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_xor_6_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 2],
  },
  {
    # round = 6 - round component = 3
    'id': 'lower_modadd_6_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_6_8', 'lower_rot_6_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODSUB', 2, None],
  },
  {
    # round = 6 - round component = 4
    'id': 'lower_rot_6_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_modadd_6_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -7],
  },
  {
    # round = 6 - round component = 5
    'id': 'lower_intermediate_output_6_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_7_6', 'lower_rot_7_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 7
  [
  {
    # round = 7 - round component = 0
    'id': 'lower_xor_7_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_7_5', 'lower_rot_8_6'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 7 - round component = 1
    'id': 'lower_xor_7_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_8_6', 'lower_rot_8_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 7 - round component = 2
    'id': 'lower_rot_7_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_xor_7_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 2],
  },
  {
    # round = 7 - round component = 3
    'id': 'lower_modadd_7_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_7_8', 'lower_rot_7_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODSUB', 2, None],
  },
  {
    # round = 7 - round component = 4
    'id': 'lower_rot_7_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_modadd_7_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -7],
  },
  {
    # round = 7 - round component = 5
    'id': 'lower_intermediate_output_7_12',
    'type': 'intermediate_output',
    'input_bit_size': 32,
    'input_id_link': ['lower_rot_8_6', 'lower_rot_8_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 32,
    'description': ['round_output'],
  },
  ],
  # round 8
  [
  {
    # round = 8 - round component = 0
    'id': 'lower_xor_8_8',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_8_5', 'lower_cipher_output_8_12'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 8 - round component = 1
    'id': 'lower_xor_8_10',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_cipher_output_8_12', 'lower_cipher_output_8_12'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
    'output_bit_size': 16,
    'description': ['XOR', 2],
  },
  {
    # round = 8 - round component = 2
    'id': 'lower_rot_8_9',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_xor_8_10'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', 2],
  },
  {
    # round = 8 - round component = 3
    'id': 'lower_modadd_8_7',
    'type': 'word_operation',
    'input_bit_size': 32,
    'input_id_link': ['lower_xor_8_8', 'lower_rot_8_9'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['MODSUB', 2, None],
  },
  {
    # round = 8 - round component = 4
    'id': 'lower_rot_8_6',
    'type': 'word_operation',
    'input_bit_size': 16,
    'input_id_link': ['lower_modadd_8_7'],
    'input_bit_positions': [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],
    'output_bit_size': 16,
    'description': ['ROTATE', -7],
  },
  ],
  ],
'cipher_reference_code': None,
}
'''