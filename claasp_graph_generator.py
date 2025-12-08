import ast
from claasp_cipher_dict import *
from graphviz import Digraph

import ast
from graphviz import Digraph

cipher_data = ast.literal_eval(data_str)

# Create a directed graph
dot = Digraph(comment='Speck32/64 Reduced to 7 Rounds')

# Set graph attributes
dot.attr(rankdir='TB', size='40,65')  # Top to bottom layout
dot.graph_attr['dpi'] = '300'  # Increase DPI for higher resolution

# Set global node attributes
dot.node_attr.update(fontname='Arial', fontsize='10', shape='box')

# Add input nodes (plaintext and key) at the top
dot.node('plaintext', 'Plaintext', shape='parallelogram', fontname='Arial', fontsize='10')
dot.node('key', 'Key', shape='parallelogram', fontname='Arial', fontsize='10')

# Dictionary to store all nodes to avoid duplicates
nodes = {'plaintext': 'input', 'key': 'input'}

# Keep track of the outputs to connect between rounds
previous_round_outputs = {'plaintext': 'plaintext', 'key': 'key'}

# Process each round and create subgraphs for rounds
for round_num, cipher_round in enumerate(cipher_data['cipher_rounds']):
    # Create a subgraph for the round
    round_subgraph = Digraph(name=f'cluster_round_{round_num}')
    round_subgraph.attr(label=f'Round {round_num}', fontsize='12', fontname='Arial', style='filled', color='lightgrey')

    # Create subgraphs for key schedule and permutation within the round
    ks = Digraph(name=f'cluster_round_{round_num}_key_schedule')
    ks.attr(label='Key Schedule', fontsize='10', fontname='Arial', style='filled', color='lightyellow')
    ks.node_attr.update(fontname='Arial', fontsize='10', shape='box')

    perm = Digraph(name=f'cluster_round_{round_num}_permutation')
    perm.attr(label='Permutation', fontsize='10', fontname='Arial', style='filled', color='lightblue')
    perm.node_attr.update(fontname='Arial', fontsize='10', shape='box')

    # List to keep track of outputs for the current round
    current_round_outputs = {}

    for operation in cipher_round:
        op_id = operation['id']
        op_tag = 'key_schedule'#operation['tag']
        op_type = operation['type']
        op_inputs = operation['input_id_link']

        # Use op_id as the label
        label = f"{op_id}"

        # Add node to appropriate subgraph
        if op_id not in nodes:
            if op_tag == 'key_schedule':
                print(op_id)
                ks.node(op_id, label)
            elif op_tag == 'permutation':
                perm.node(op_id, label)
            else:
                round_subgraph.node(op_id, label)
            nodes[op_id] = op_tag

        # Add edges based on input_id_link
        for input_link in op_inputs:
            if input_link:
                if input_link in nodes:
                    dot.edge(input_link, op_id)
                else:
                    # Add the input node if it hasn't been added yet
                    dot.node(input_link, input_link)
                    dot.edge(input_link, op_id)
                    nodes[input_link] = 'unknown'

        # Keep track of outputs for connecting to the next round
        # You can adjust this logic based on your specific needs
        #if op_type == 'intermediate_output' or op_type == 'cipher_output':
        #    output_name = f"round_{round_num}_{op_id}"
        #    dot.node(output_name, op_id, shape='parallelogram', fontname='Arial', fontsize='10')
        #    dot.edge(op_id, output_name)
        #    current_round_outputs[op_tag] = output_name
        #    nodes[output_name] = 'output'

    # Combine key schedule and permutation subgraphs into the round subgraph
    # Arrange them horizontally
    round_subgraph.subgraph(ks)
    round_subgraph.subgraph(perm)

    # Set ranks to arrange key schedule and permutation side by side
    round_subgraph.attr(rank='same')

    # Add the round subgraph to the main graph
    dot.subgraph(round_subgraph)

    # Connect outputs from this round to the next round's inputs
    # (if applicable)
    previous_round_outputs = current_round_outputs

dot.render("original_"+cipher_data["cipher_id"], format='png', view=True)


