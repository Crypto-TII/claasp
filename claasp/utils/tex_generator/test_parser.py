#!/usr/bin/env sage
import subprocess

from sage.all import *
from copy import deepcopy

import networkx as nx

from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values, set_fixed_variables, \
    integer_to_bit_list
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY, INTERMEDIATE_OUTPUT

simon = SimonBlockCipher(number_of_rounds=1)
milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(simon)
pt = [set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=list(range(32)),
        bit_values=integer_to_bit_list(0x0, 32, 'big')),
      set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=list(range(64)),
        bit_values=[0] * 64)]
trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(pt)

def separate_inputs_from_solution(trail):
    cipher = trail['cipher']
    if {INPUT_PLAINTEXT, INPUT_KEY} > set(cipher.inputs):
        raise ValueError("Cipher object should have a key and a plaintext.")
    graph_cipher = create_networkx_graph_from_input_ids(cipher)
    key_schedule_component_ids = nx.descendants(graph_cipher, INPUT_KEY)-nx.descendants(graph_cipher, INPUT_PLAINTEXT)
    key_schedule_component_ids |= set([_ for i in key_schedule_component_ids for _ in graph_cipher.predecessors(i)])
    # round_keys = set([_ for i in nx.descendants(graph_cipher, INPUT_PLAINTEXT) for _ in graph_cipher.predecessors(i)]).intersection(key_schedule_component_ids)
    round_keys = {id for id in key_schedule_component_ids if INTERMEDIATE_OUTPUT in id}

    components_values = trail['components_values']
    dict_key = {}
    dict_plaintext = {}

    for key, value in components_values.items():
        if key in key_schedule_component_ids:
            dict_key[key] = value
        else:
            dict_plaintext[key] = value
    split_trail = deepcopy(trail)
    split_trail['components_values'] = {'plaintext': dict_plaintext, 'key': dict_key}
    return split_trail


from claasp.utils.tex_generator.parser import Drawer, read_from_trail
attributes = read_from_trail(trail)
drawer = Drawer(attributes)
drawer.draw()
os.system(f"/Library/TeX/texbin/latexmk -r .latexmkrc -pdf -cd {drawer.output_file_name}")
os.system("/Library/TeX/texbin/latexmk -c")
# subprocess.run(["open", 'simon.pdf'])