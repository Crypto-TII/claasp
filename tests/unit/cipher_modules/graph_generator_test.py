from claasp.cipher_modules.graph_generator import split_cipher_graph_into_top_bottom
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids, _get_descendants_subgraph


e0_graph_nodes = [
    'rot_0_8', 'rot_1_14', 'xor_1_4', 'rot_0_11', 'xor_0_1', 'modadd_0_21', 'modadd_0_9', 'rot_0_20', 'xor_1_22',
    'xor_0_4', 'modadd_0_0', 'modadd_0_15', 'xor_1_7', 'xor_0_7', 'xor_1_16', 'modadd_1_18', 'xor_1_1', 'modadd_0_18',
    'rot_1_11', 'modadd_1_15', 'xor_1_13', 'plaintext', 'rot_0_5', 'rot_0_23', 'modadd_1_12', 'xor_0_19', 'rot_0_2',
    'rot_1_17', 'modadd_1_21', 'xor_0_10', 'modadd_1_0', 'modadd_1_9', 'modadd_0_6', 'modadd_0_3', 'modadd_1_6',
    'rot_0_17', 'xor_0_22', 'rot_1_20', 'modadd_0_12', 'rot_1_23', 'rot_0_14', 'rot_1_2', 'xor_1_10', 'rot_1_5',
    'xor_1_19', 'xor_0_16', 'modadd_1_3', 'rot_1_8', 'xor_0_13'
]

e1_graph_nodes = [
    'xor_2_7', 'rot_2_8', 'modadd_2_9', 'xor_2_10', 'rot_2_11', 'modadd_3_6', 'xor_3_7', 'rot_3_8', 'modadd_3_9',
    'xor_3_10', 'rot_3_11', 'xor_2_1', 'rot_2_2', 'modadd_2_3', 'xor_2_4', 'rot_2_5', 'modadd_3_0', 'xor_3_1',
    'rot_3_2', 'modadd_3_3', 'xor_3_4', 'rot_3_5', 'xor_2_19', 'rot_2_20', 'modadd_2_21', 'xor_2_22', 'rot_2_23',
    'modadd_3_18', 'xor_3_19', 'rot_3_20', 'modadd_3_21', 'xor_3_22', 'rot_3_23', 'xor_2_13', 'rot_2_14', 'modadd_2_15',
    'xor_2_16', 'rot_2_17', 'modadd_3_12', 'xor_3_13', 'rot_3_14', 'modadd_3_15', 'xor_3_16', 'rot_3_17',
    'cipher_output_3_24', 'intermediate_output_2_24'
]

e0_graph_edges = [
    ('rot_0_8', 'modadd_0_9'), ('rot_0_8', 'xor_1_7'), ('rot_1_14', 'modadd_1_15'), ('xor_1_4', 'rot_1_5'),
    ('rot_0_11', 'modadd_1_6'), ('rot_0_11', 'xor_1_10'), ('xor_0_1', 'rot_0_2'), ('modadd_0_21', 'xor_0_22'),
    ('modadd_0_21', 'modadd_1_21'), ('modadd_0_9', 'xor_0_10'), ('modadd_0_9', 'modadd_1_9'),
    ('rot_0_20', 'modadd_0_21'), ('rot_0_20', 'xor_1_19'), ('xor_1_22', 'rot_1_23'), ('xor_0_4', 'rot_0_5'),
    ('modadd_0_0', 'xor_0_1'), ('modadd_0_0', 'modadd_1_0'), ('modadd_0_15', 'xor_0_16'),
    ('modadd_0_15', 'modadd_1_15'), ('xor_1_7', 'rot_1_8'), ('xor_0_7', 'rot_0_8'), ('xor_1_16', 'rot_1_17'),
    ('modadd_1_18', 'xor_1_19'), ('xor_1_1', 'rot_1_2'), ('modadd_0_18', 'xor_0_19'), ('modadd_0_18', 'modadd_1_18'),
    ('modadd_1_15', 'xor_1_16'), ('xor_1_13', 'rot_1_14'), ('plaintext', 'modadd_0_0'), ('plaintext', 'xor_0_1'),
    ('plaintext', 'modadd_0_3'), ('plaintext', 'xor_0_4'), ('plaintext', 'modadd_0_6'), ('plaintext', 'xor_0_7'),
    ('plaintext', 'modadd_0_9'), ('plaintext', 'xor_0_10'), ('plaintext', 'modadd_0_12'), ('plaintext', 'xor_0_13'),
    ('plaintext', 'modadd_0_15'), ('plaintext', 'xor_0_16'), ('plaintext', 'modadd_0_18'), ('plaintext', 'xor_0_19'),
    ('plaintext', 'modadd_0_21'), ('plaintext', 'xor_0_22'), ('rot_0_5', 'modadd_1_0'), ('rot_0_5', 'xor_1_4'),
    ('rot_0_23', 'modadd_1_18'), ('rot_0_23', 'xor_1_22'), ('modadd_1_12', 'xor_1_13'), ('xor_0_19', 'rot_0_20'),
    ('rot_0_2', 'modadd_0_3'), ('rot_0_2', 'xor_1_1'), ('modadd_1_21', 'xor_1_22'), ('xor_0_10', 'rot_0_11'),
    ('modadd_1_0', 'xor_1_1'), ('modadd_1_9', 'xor_1_10'), ('modadd_0_6', 'xor_0_7'), ('modadd_0_6', 'modadd_1_6'),
    ('modadd_0_3', 'xor_0_4'), ('modadd_0_3', 'modadd_1_3'), ('modadd_1_6', 'xor_1_7'), ('rot_0_17', 'modadd_1_12'),
    ('rot_0_17', 'xor_1_16'), ('xor_0_22', 'rot_0_23'), ('rot_1_20', 'modadd_1_21'), ('modadd_0_12', 'xor_0_13'),
    ('modadd_0_12', 'modadd_1_12'), ('rot_0_14', 'modadd_0_15'), ('rot_0_14', 'xor_1_13'), ('rot_1_2', 'modadd_1_3'),
    ('xor_1_10', 'rot_1_11'), ('xor_1_19', 'rot_1_20'), ('xor_0_16', 'rot_0_17'), ('modadd_1_3', 'xor_1_4'),
    ('rot_1_8', 'modadd_1_9'), ('xor_0_13', 'rot_0_14')
]

e1_graph_edges = [
    ('xor_2_7', 'xor_2_7'), ('xor_2_7', 'rot_2_8'), ('xor_2_7', 'modadd_2_9'), ('xor_2_7', 'xor_2_10'),
    ('xor_2_7', 'rot_2_11'), ('xor_2_7', 'modadd_3_6'), ('xor_2_7', 'xor_3_7'), ('xor_2_7', 'rot_3_8'),
    ('xor_2_7', 'modadd_3_9'), ('xor_2_7', 'xor_3_10'), ('xor_2_7', 'rot_3_11'), ('modadd_2_9', 'modadd_2_9'),
    ('modadd_2_9', 'xor_2_10'), ('modadd_2_9', 'rot_2_11'), ('modadd_2_9', 'modadd_3_6'), ('modadd_2_9', 'xor_3_7'),
    ('modadd_2_9', 'rot_3_8'), ('modadd_2_9', 'modadd_3_9'), ('modadd_2_9', 'xor_3_10'), ('modadd_2_9', 'rot_3_11'),
    ('xor_2_10', 'xor_2_10'), ('xor_2_10', 'rot_2_11'), ('xor_2_10', 'modadd_3_6'), ('xor_2_10', 'xor_3_7'),
    ('xor_2_10', 'rot_3_8'), ('xor_2_10', 'modadd_3_9'), ('xor_2_10', 'xor_3_10'), ('xor_2_10', 'rot_3_11'),
    ('xor_2_1', 'xor_2_1'), ('xor_2_1', 'rot_2_2'), ('xor_2_1', 'modadd_2_3'), ('xor_2_1', 'xor_2_4'),
    ('xor_2_1', 'rot_2_5'), ('xor_2_1', 'modadd_3_0'), ('xor_2_1', 'xor_3_1'), ('xor_2_1', 'rot_3_2'),
    ('xor_2_1', 'modadd_3_3'), ('xor_2_1', 'xor_3_4'), ('xor_2_1', 'rot_3_5'), ('modadd_2_3', 'modadd_2_3'),
    ('modadd_2_3', 'xor_2_4'), ('modadd_2_3', 'rot_2_5'), ('modadd_2_3', 'modadd_3_0'), ('modadd_2_3', 'xor_3_1'),
    ('modadd_2_3', 'rot_3_2'), ('modadd_2_3', 'modadd_3_3'), ('modadd_2_3', 'xor_3_4'), ('modadd_2_3', 'rot_3_5'),
    ('xor_2_4', 'xor_2_4'), ('xor_2_4', 'rot_2_5'), ('xor_2_4', 'modadd_3_0'), ('xor_2_4', 'xor_3_1'),
    ('xor_2_4', 'rot_3_2'), ('xor_2_4', 'modadd_3_3'), ('xor_2_4', 'xor_3_4'), ('xor_2_4', 'rot_3_5'),
    ('xor_2_19', 'xor_2_19'), ('xor_2_19', 'rot_2_20'), ('xor_2_19', 'modadd_2_21'), ('xor_2_19', 'xor_2_22'),
    ('xor_2_19', 'rot_2_23'), ('xor_2_19', 'modadd_3_18'), ('xor_2_19', 'xor_3_19'), ('xor_2_19', 'rot_3_20'),
    ('xor_2_19', 'modadd_3_21'), ('xor_2_19', 'xor_3_22'), ('xor_2_19', 'rot_3_23'), ('modadd_2_21', 'modadd_2_21'),
    ('modadd_2_21', 'xor_2_22'), ('modadd_2_21', 'rot_2_23'), ('modadd_2_21', 'modadd_3_18'),
    ('modadd_2_21', 'xor_3_19'), ('modadd_2_21', 'rot_3_20'), ('modadd_2_21', 'modadd_3_21'),
    ('modadd_2_21', 'xor_3_22'), ('modadd_2_21', 'rot_3_23'), ('xor_2_22', 'xor_2_22'), ('xor_2_22', 'rot_2_23'),
    ('xor_2_22', 'modadd_3_18'), ('xor_2_22', 'xor_3_19'), ('xor_2_22', 'rot_3_20'), ('xor_2_22', 'modadd_3_21'),
    ('xor_2_22', 'xor_3_22'), ('xor_2_22', 'rot_3_23'), ('xor_2_13', 'xor_2_13'), ('xor_2_13', 'rot_2_14'),
    ('xor_2_13', 'modadd_2_15'), ('xor_2_13', 'xor_2_16'), ('xor_2_13', 'rot_2_17'), ('xor_2_13', 'modadd_3_12'),
    ('xor_2_13', 'xor_3_13'), ('xor_2_13', 'rot_3_14'), ('xor_2_13', 'modadd_3_15'), ('xor_2_13', 'xor_3_16'),
    ('xor_2_13', 'rot_3_17'), ('modadd_2_15', 'modadd_2_15'), ('modadd_2_15', 'xor_2_16'), ('modadd_2_15', 'rot_2_17'),
    ('modadd_2_15', 'modadd_3_12'), ('modadd_2_15', 'xor_3_13'), ('modadd_2_15', 'rot_3_14'),
    ('modadd_2_15', 'modadd_3_15'), ('modadd_2_15', 'xor_3_16'), ('modadd_2_15', 'rot_3_17'), ('xor_2_16', 'xor_2_16'),
    ('xor_2_16', 'rot_2_17'), ('xor_2_16', 'modadd_3_12'), ('xor_2_16', 'xor_3_13'), ('xor_2_16', 'rot_3_14'),
    ('xor_2_16', 'modadd_3_15'), ('xor_2_16', 'xor_3_16'), ('xor_2_16', 'rot_3_17'), ('xor_2_19', 'cipher_output_3_24'),
    ('modadd_2_3', 'cipher_output_3_24'), ('xor_2_7', 'intermediate_output_2_24'),
    ('xor_2_16', 'intermediate_output_2_24'), ('xor_2_4', 'intermediate_output_2_24'),
    ('xor_2_10', 'intermediate_output_2_24'), ('xor_2_1', 'cipher_output_3_24'),
    ('xor_2_13', 'intermediate_output_2_24'), ('modadd_2_9', 'cipher_output_3_24'),
    ('xor_2_19', 'intermediate_output_2_24'), ('xor_2_22', 'cipher_output_3_24'), ('xor_2_13', 'cipher_output_3_24'),
    ('modadd_2_21', 'cipher_output_3_24'), ('modadd_2_3', 'intermediate_output_2_24'),
    ('modadd_2_15', 'cipher_output_3_24'), ('xor_2_1', 'intermediate_output_2_24'),
    ('modadd_2_9', 'intermediate_output_2_24'), ('xor_2_22', 'intermediate_output_2_24'),
    ('xor_2_7', 'cipher_output_3_24'), ('xor_2_16', 'cipher_output_3_24'), ('xor_2_4', 'cipher_output_3_24'),
    ('modadd_2_21', 'intermediate_output_2_24'), ('xor_2_10', 'cipher_output_3_24'),
    ('modadd_2_15', 'intermediate_output_2_24')
]


def test_split_cipher_graph_into_top_bottom():
    chacha = ChachaPermutation(number_of_rounds=4, round_mode=ROUND_MODE_HALF)

    e0_graph_nodes = ['modadd_0_0', 'xor_0_1', 'rot_0_2', 'modadd_0_3', 'xor_0_4', 'rot_0_5', 'modadd_0_6', 'xor_0_7',
                      'rot_0_8', 'modadd_0_9', 'xor_0_10', 'rot_0_11', 'modadd_0_12', 'xor_0_13', 'rot_0_14',
                      'modadd_0_15', 'xor_0_16', 'rot_0_17', 'modadd_0_18', 'xor_0_19', 'rot_0_20', 'modadd_0_21',
                      'xor_0_22', 'rot_0_23', 'intermediate_output_0_24', 'modadd_1_0', 'xor_1_1', 'rot_1_2',
                      'modadd_1_3', 'xor_1_4', 'rot_1_5', 'modadd_1_6', 'xor_1_7', 'rot_1_8', 'modadd_1_9', 'xor_1_10',
                      'rot_1_11', 'modadd_1_12', 'xor_1_13', 'rot_1_14', 'modadd_1_15', 'xor_1_16', 'rot_1_17',
                      'modadd_1_18', 'xor_1_19', 'rot_1_20', 'modadd_1_21', 'xor_1_22', 'rot_1_23',
                      'intermediate_output_1_24', 'plaintext']
    e1_graph_nodes = ['xor_2_7', 'rot_2_8', 'modadd_2_9', 'xor_2_10', 'rot_2_11', 'intermediate_output_2_24',
                      'modadd_3_6', 'xor_3_7', 'rot_3_8', 'modadd_3_9', 'xor_3_10', 'rot_3_11', 'cipher_output_3_24',
                      'xor_2_1', 'rot_2_2', 'modadd_2_3', 'xor_2_4', 'rot_2_5', 'modadd_3_0', 'xor_3_1', 'rot_3_2',
                      'modadd_3_3', 'xor_3_4', 'rot_3_5', 'xor_2_19', 'rot_2_20', 'modadd_2_21', 'xor_2_22', 'rot_2_23',
                      'modadd_3_18', 'xor_3_19', 'rot_3_20', 'modadd_3_21', 'xor_3_22', 'rot_3_23', 'xor_2_13',
                      'rot_2_14', 'modadd_2_15', 'xor_2_16', 'rot_2_17', 'modadd_3_12', 'xor_3_13', 'rot_3_14',
                      'modadd_3_15', 'xor_3_16', 'rot_3_17']
    e0_graph_edges = [('modadd_0_0', 'xor_0_1'), ('modadd_0_0', 'intermediate_output_0_24'),
                      ('modadd_0_0', 'modadd_1_0'), ('xor_0_1', 'rot_0_2'), ('rot_0_2', 'modadd_0_3'),
                      ('rot_0_2', 'intermediate_output_0_24'), ('rot_0_2', 'xor_1_1'), ('modadd_0_3', 'xor_0_4'),
                      ('modadd_0_3', 'intermediate_output_0_24'), ('modadd_0_3', 'modadd_1_3'), ('xor_0_4', 'rot_0_5'),
                      ('rot_0_5', 'intermediate_output_0_24'), ('rot_0_5', 'modadd_1_0'), ('rot_0_5', 'xor_1_4'),
                      ('modadd_0_6', 'xor_0_7'), ('modadd_0_6', 'intermediate_output_0_24'),
                      ('modadd_0_6', 'modadd_1_6'), ('xor_0_7', 'rot_0_8'), ('rot_0_8', 'modadd_0_9'),
                      ('rot_0_8', 'intermediate_output_0_24'), ('rot_0_8', 'xor_1_7'), ('modadd_0_9', 'xor_0_10'),
                      ('modadd_0_9', 'intermediate_output_0_24'), ('modadd_0_9', 'modadd_1_9'),
                      ('xor_0_10', 'rot_0_11'), ('rot_0_11', 'intermediate_output_0_24'), ('rot_0_11', 'modadd_1_6'),
                      ('rot_0_11', 'xor_1_10'), ('modadd_0_12', 'xor_0_13'),
                      ('modadd_0_12', 'intermediate_output_0_24'), ('modadd_0_12', 'modadd_1_12'),
                      ('xor_0_13', 'rot_0_14'), ('rot_0_14', 'modadd_0_15'), ('rot_0_14', 'intermediate_output_0_24'),
                      ('rot_0_14', 'xor_1_13'), ('modadd_0_15', 'xor_0_16'),
                      ('modadd_0_15', 'intermediate_output_0_24'), ('modadd_0_15', 'modadd_1_15'),
                      ('xor_0_16', 'rot_0_17'), ('rot_0_17', 'intermediate_output_0_24'), ('rot_0_17', 'modadd_1_12'),
                      ('rot_0_17', 'xor_1_16'), ('modadd_0_18', 'xor_0_19'),
                      ('modadd_0_18', 'intermediate_output_0_24'), ('modadd_0_18', 'modadd_1_18'),
                      ('xor_0_19', 'rot_0_20'), ('rot_0_20', 'modadd_0_21'), ('rot_0_20', 'intermediate_output_0_24'),
                      ('rot_0_20', 'xor_1_19'), ('modadd_0_21', 'xor_0_22'),
                      ('modadd_0_21', 'intermediate_output_0_24'), ('modadd_0_21', 'modadd_1_21'),
                      ('xor_0_22', 'rot_0_23'), ('rot_0_23', 'intermediate_output_0_24'), ('rot_0_23', 'modadd_1_18'),
                      ('rot_0_23', 'xor_1_22'), ('modadd_1_0', 'xor_1_1'), ('modadd_1_0', 'intermediate_output_1_24'),
                      ('xor_1_1', 'rot_1_2'), ('rot_1_2', 'modadd_1_3'), ('rot_1_2', 'intermediate_output_1_24'),
                      ('modadd_1_3', 'xor_1_4'), ('modadd_1_3', 'intermediate_output_1_24'), ('xor_1_4', 'rot_1_5'),
                      ('rot_1_5', 'intermediate_output_1_24'), ('modadd_1_6', 'xor_1_7'),
                      ('modadd_1_6', 'intermediate_output_1_24'), ('xor_1_7', 'rot_1_8'), ('rot_1_8', 'modadd_1_9'),
                      ('rot_1_8', 'intermediate_output_1_24'), ('modadd_1_9', 'xor_1_10'),
                      ('modadd_1_9', 'intermediate_output_1_24'), ('xor_1_10', 'rot_1_11'),
                      ('rot_1_11', 'intermediate_output_1_24'), ('modadd_1_12', 'xor_1_13'),
                      ('modadd_1_12', 'intermediate_output_1_24'), ('xor_1_13', 'rot_1_14'),
                      ('rot_1_14', 'modadd_1_15'), ('rot_1_14', 'intermediate_output_1_24'),
                      ('modadd_1_15', 'xor_1_16'), ('modadd_1_15', 'intermediate_output_1_24'),
                      ('xor_1_16', 'rot_1_17'), ('rot_1_17', 'intermediate_output_1_24'), ('modadd_1_18', 'xor_1_19'),
                      ('modadd_1_18', 'intermediate_output_1_24'), ('xor_1_19', 'rot_1_20'),
                      ('rot_1_20', 'modadd_1_21'), ('rot_1_20', 'intermediate_output_1_24'),
                      ('modadd_1_21', 'xor_1_22'), ('modadd_1_21', 'intermediate_output_1_24'),
                      ('xor_1_22', 'rot_1_23'), ('rot_1_23', 'intermediate_output_1_24'), ('plaintext', 'modadd_0_0'),
                      ('plaintext', 'xor_0_1'), ('plaintext', 'modadd_0_3'), ('plaintext', 'xor_0_4'),
                      ('plaintext', 'modadd_0_6'), ('plaintext', 'xor_0_7'), ('plaintext', 'modadd_0_9'),
                      ('plaintext', 'xor_0_10'), ('plaintext', 'modadd_0_12'), ('plaintext', 'xor_0_13'),
                      ('plaintext', 'modadd_0_15'), ('plaintext', 'xor_0_16'), ('plaintext', 'modadd_0_18'),
                      ('plaintext', 'xor_0_19'), ('plaintext', 'modadd_0_21'), ('plaintext', 'xor_0_22')]
    e1_graph_edges = [('xor_2_7', 'xor_2_7'), ('xor_2_7', 'rot_2_8'), ('xor_2_7', 'modadd_2_9'),
                      ('xor_2_7', 'xor_2_10'), ('xor_2_7', 'rot_2_11'), ('xor_2_7', 'intermediate_output_2_24'),
                      ('xor_2_7', 'modadd_3_6'), ('xor_2_7', 'xor_3_7'), ('xor_2_7', 'rot_3_8'),
                      ('xor_2_7', 'modadd_3_9'), ('xor_2_7', 'xor_3_10'), ('xor_2_7', 'rot_3_11'),
                      ('xor_2_7', 'cipher_output_3_24'), ('modadd_2_9', 'modadd_2_9'), ('modadd_2_9', 'xor_2_10'),
                      ('modadd_2_9', 'rot_2_11'), ('modadd_2_9', 'intermediate_output_2_24'),
                      ('modadd_2_9', 'modadd_3_6'), ('modadd_2_9', 'xor_3_7'), ('modadd_2_9', 'rot_3_8'),
                      ('modadd_2_9', 'modadd_3_9'), ('modadd_2_9', 'xor_3_10'), ('modadd_2_9', 'rot_3_11'),
                      ('modadd_2_9', 'cipher_output_3_24'), ('xor_2_10', 'xor_2_10'), ('xor_2_10', 'rot_2_11'),
                      ('xor_2_10', 'intermediate_output_2_24'), ('xor_2_10', 'modadd_3_6'), ('xor_2_10', 'xor_3_7'),
                      ('xor_2_10', 'rot_3_8'), ('xor_2_10', 'modadd_3_9'), ('xor_2_10', 'xor_3_10'),
                      ('xor_2_10', 'rot_3_11'), ('xor_2_10', 'cipher_output_3_24'), ('xor_2_1', 'xor_2_1'),
                      ('xor_2_1', 'rot_2_2'), ('xor_2_1', 'modadd_2_3'), ('xor_2_1', 'xor_2_4'), ('xor_2_1', 'rot_2_5'),
                      ('xor_2_1', 'intermediate_output_2_24'), ('xor_2_1', 'modadd_3_0'), ('xor_2_1', 'xor_3_1'),
                      ('xor_2_1', 'rot_3_2'), ('xor_2_1', 'modadd_3_3'), ('xor_2_1', 'xor_3_4'), ('xor_2_1', 'rot_3_5'),
                      ('xor_2_1', 'cipher_output_3_24'), ('modadd_2_3', 'modadd_2_3'), ('modadd_2_3', 'xor_2_4'),
                      ('modadd_2_3', 'rot_2_5'), ('modadd_2_3', 'intermediate_output_2_24'),
                      ('modadd_2_3', 'modadd_3_0'), ('modadd_2_3', 'xor_3_1'), ('modadd_2_3', 'rot_3_2'),
                      ('modadd_2_3', 'modadd_3_3'), ('modadd_2_3', 'xor_3_4'), ('modadd_2_3', 'rot_3_5'),
                      ('modadd_2_3', 'cipher_output_3_24'), ('xor_2_4', 'xor_2_4'), ('xor_2_4', 'rot_2_5'),
                      ('xor_2_4', 'intermediate_output_2_24'), ('xor_2_4', 'modadd_3_0'), ('xor_2_4', 'xor_3_1'),
                      ('xor_2_4', 'rot_3_2'), ('xor_2_4', 'modadd_3_3'), ('xor_2_4', 'xor_3_4'), ('xor_2_4', 'rot_3_5'),
                      ('xor_2_4', 'cipher_output_3_24'), ('xor_2_19', 'xor_2_19'), ('xor_2_19', 'rot_2_20'),
                      ('xor_2_19', 'modadd_2_21'), ('xor_2_19', 'xor_2_22'), ('xor_2_19', 'rot_2_23'),
                      ('xor_2_19', 'intermediate_output_2_24'), ('xor_2_19', 'modadd_3_18'), ('xor_2_19', 'xor_3_19'),
                      ('xor_2_19', 'rot_3_20'), ('xor_2_19', 'modadd_3_21'), ('xor_2_19', 'xor_3_22'),
                      ('xor_2_19', 'rot_3_23'), ('xor_2_19', 'cipher_output_3_24'), ('modadd_2_21', 'modadd_2_21'),
                      ('modadd_2_21', 'xor_2_22'), ('modadd_2_21', 'rot_2_23'),
                      ('modadd_2_21', 'intermediate_output_2_24'), ('modadd_2_21', 'modadd_3_18'),
                      ('modadd_2_21', 'xor_3_19'), ('modadd_2_21', 'rot_3_20'), ('modadd_2_21', 'modadd_3_21'),
                      ('modadd_2_21', 'xor_3_22'), ('modadd_2_21', 'rot_3_23'), ('modadd_2_21', 'cipher_output_3_24'),
                      ('xor_2_22', 'xor_2_22'), ('xor_2_22', 'rot_2_23'), ('xor_2_22', 'intermediate_output_2_24'),
                      ('xor_2_22', 'modadd_3_18'), ('xor_2_22', 'xor_3_19'), ('xor_2_22', 'rot_3_20'),
                      ('xor_2_22', 'modadd_3_21'), ('xor_2_22', 'xor_3_22'), ('xor_2_22', 'rot_3_23'),
                      ('xor_2_22', 'cipher_output_3_24'), ('xor_2_13', 'xor_2_13'), ('xor_2_13', 'rot_2_14'),
                      ('xor_2_13', 'modadd_2_15'), ('xor_2_13', 'xor_2_16'), ('xor_2_13', 'rot_2_17'),
                      ('xor_2_13', 'intermediate_output_2_24'), ('xor_2_13', 'modadd_3_12'), ('xor_2_13', 'xor_3_13'),
                      ('xor_2_13', 'rot_3_14'), ('xor_2_13', 'modadd_3_15'), ('xor_2_13', 'xor_3_16'),
                      ('xor_2_13', 'rot_3_17'), ('xor_2_13', 'cipher_output_3_24'), ('modadd_2_15', 'modadd_2_15'),
                      ('modadd_2_15', 'xor_2_16'), ('modadd_2_15', 'rot_2_17'),
                      ('modadd_2_15', 'intermediate_output_2_24'), ('modadd_2_15', 'modadd_3_12'),
                      ('modadd_2_15', 'xor_3_13'), ('modadd_2_15', 'rot_3_14'), ('modadd_2_15', 'modadd_3_15'),
                      ('modadd_2_15', 'xor_3_16'), ('modadd_2_15', 'rot_3_17'), ('modadd_2_15', 'cipher_output_3_24'),
                      ('xor_2_16', 'xor_2_16'), ('xor_2_16', 'rot_2_17'), ('xor_2_16', 'intermediate_output_2_24'),
                      ('xor_2_16', 'modadd_3_12'), ('xor_2_16', 'xor_3_13'), ('xor_2_16', 'rot_3_14'),
                      ('xor_2_16', 'modadd_3_15'), ('xor_2_16', 'xor_3_16'), ('xor_2_16', 'rot_3_17'),
                      ('xor_2_16', 'cipher_output_3_24')]

    e0_end = [
        "modadd_1_6",
        "rot_1_17",
        "rot_1_2",
        "modadd_1_21",

        "modadd_1_0",
        "rot_1_20",
        "modadd_1_15",
        "rot_1_11",

        "modadd_1_18",
        "rot_1_14",
        "modadd_1_9",
        "rot_1_5",

        "modadd_1_12",
        "rot_1_8",
        "modadd_1_3",
        "rot_1_23"
    ]

    e1_start = [
        # "modadd_2_6",
        "xor_2_7",
        "modadd_2_9",
        "xor_2_10",

        # "modadd_2_0",
        "xor_2_1",
        "modadd_2_3",
        "xor_2_4",

        # "modadd_2_18",
        "xor_2_19",
        "modadd_2_21",
        "xor_2_22",

        # "modadd_2_12",
        "xor_2_13",
        "modadd_2_15",
        "xor_2_16"
    ]

    e0_graph, e1_graph = split_cipher_graph_into_top_bottom(chacha, e0_end, e1_start)
    assert set(e0_graph.nodes()) == set(e0_graph_nodes)
    assert set(e1_graph.nodes()) == set(e1_graph_nodes)
    assert set(e0_graph.edges()) == set(e0_graph_edges)
    assert set(e1_graph.edges()) == set(e1_graph_edges)


def test_get_descendants_subgraph():
    speck_cipher = SpeckBlockCipher(number_of_rounds=3)
    graph_cipher = create_networkx_graph_from_input_ids(speck_cipher)
    descendants_subgraph1 = _get_descendants_subgraph(graph_cipher, ['plaintext'])
    descendants_subgraph2 = _get_descendants_subgraph(graph_cipher, ['modadd_0_1'])
    descendants_subgraph1_nodes = [
        'plaintext', 'rot_0_0', 'modadd_0_1', 'xor_0_2', 'xor_0_4', 'intermediate_output_0_6', 'modadd_1_7', 'xor_1_8',
        'xor_1_10', 'intermediate_output_1_12', 'modadd_2_7', 'xor_2_8', 'xor_2_10', 'cipher_output_2_12', 'rot_2_9',
        'rot_2_6', 'rot_1_9', 'rot_1_6', 'rot_0_3'
    ]
    descendants_subgraph2_nodes = [
        'modadd_0_1', 'xor_0_2', 'xor_0_4', 'intermediate_output_0_6', 'modadd_1_7', 'xor_1_8', 'xor_1_10',
        'intermediate_output_1_12', 'modadd_2_7', 'xor_2_8', 'xor_2_10', 'cipher_output_2_12', 'rot_2_9', 'rot_2_6',
        'rot_1_9', 'rot_1_6'
    ]
    assert set(descendants_subgraph1.nodes()) == set(descendants_subgraph1_nodes)
    assert set(descendants_subgraph2.nodes()) == set(descendants_subgraph2_nodes)
