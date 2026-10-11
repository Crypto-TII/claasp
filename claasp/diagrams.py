"""Generic typed DAG diagrams. Layout is separate from executable semantics.

Bit positions follow CLAASP's MSB-first convention. Native descriptions are
retained verbatim; unsupported executable operations fail explicitly. No cipher
names or reference diagrams participate in layout or state inference.
"""
import copy
import json
from claasp.cipher import Cipher

SCHEMA = 'claasp-diagrams/1'


def validate(ir):
    if ir.get('schema') != SCHEMA:
        raise ValueError('Unsupported diagram schema')
    if type(ir.get('output_bits')) is not int or ir['output_bits'] <= 0:
        raise ValueError('Missing or invalid output width')
    known = {}
    for item in ir['inputs']:
        if item['id'] in known or type(item['bits']) is not int or item['bits'] <= 0:
            raise ValueError('Invalid or duplicate input')
        known[item['id']] = item['bits']
    last_round = -1
    for n in ir['nodes']:
        if n['id'] in known or type(n['bits']) is not int or n['bits'] <= 0 or type(n['round']) is not int or n['round'] < 0 or n['round'] < last_round or type(n['input_bits']) is not int or n['input_bits'] < 0 or not isinstance(n['description'], list):
            raise ValueError('Invalid node identity, width or round order')
        last_round = n['round']
        total = 0
        for edge in n['operands']:
            if edge['source'] not in known:
                raise ValueError('Unknown, forward or cyclic bit link')
            positions = edge['positions']
            if not isinstance(positions, list) or any(type(b) is not int or b < 0 or b >= known[edge['source']] for b in positions):
                raise ValueError('Invalid bit selection')
            total += len(positions)
        if total != n['input_bits']:
            raise ValueError('Input width disagrees with ordered bit links')
        known[n['id']] = n['bits']
    outputs = [n for n in ir['nodes'] if n['type'] == 'cipher_output']
    if len(outputs) != 1 or outputs[0]['bits'] != ir['output_bits']:
        raise ValueError('Require one explicitly sized native cipher output')
    if type(ir['rounds']) is not int or ir['rounds'] <= 0 or last_round >= ir['rounds']:
        raise ValueError('Round outside declared range')
    return ir


def from_cipher(cipher, *, roles=None):
    d = cipher.as_python_dictionary()
    roles = roles or {}
    ir = {'schema': SCHEMA, 'name': cipher.family_name, 'cipher_type': d['cipher_type'],
          'inputs': [{'id': name, 'bits': bits, 'role': roles.get(name, 'unspecified')}
                     for name, bits in zip(d['cipher_inputs'], d['cipher_inputs_bit_size'])],
          'output_bits': d['cipher_output_bit_size'], 'rounds': d['cipher_number_of_rounds'], 'nodes': []}
    for r, components in enumerate(d['cipher_rounds']):
        for c in components:
            ir['nodes'].append({'id': c['id'], 'type': c['type'], 'bits': c['output_bit_size'],
                                'round': r, 'input_bits': c['input_bit_size'],
                                'operands': [{'source': a, 'positions': copy.deepcopy(b)} for a,b in
                                             zip(c['input_id_link'], c['input_bit_positions']) if b],
                                'description': copy.deepcopy(c['description'])})
    return validate(ir)


def to_cipher(ir):
    validate(ir)
    cipher = Cipher(ir['name'], ir['cipher_type'], [i['id'] for i in ir['inputs']],
                    [i['bits'] for i in ir['inputs']], ir['output_bits'])
    cipher.diagram_input_roles = {i['id']: i['role'] for i in ir['inputs']}
    links = {i['id']: i['id'] for i in ir['inputs']}
    current_round = -1
    for n in ir['nodes']:
        while current_round < n['round']:
            cipher.add_round(); current_round += 1
        ids = [links[e['source']] for e in n['operands']]
        pos = [e['positions'] for e in n['operands']]
        desc = n['description']; typ = n['type']; bits = n['bits']
        if typ == 'constant':
            component = cipher.add_constant_component(bits, int(desc[0], 0))
        elif typ == 'word_operation':
            op = desc[0].lower()
            if op not in {'xor','and','or','not','modadd','modsub','modmul','rotate','shift','reverse','variable_rotate','variable_shift'}:
                raise ValueError(f'Unsupported executable word operation: {op}')
            args = [ids, pos, bits]
            if op in {'rotate','shift','variable_rotate','variable_shift'}: args.append(desc[1])
            if op in {'modadd','modsub','modmul'}: args.append(desc[2] if len(desc)>2 else None)
            component = getattr(cipher, f'add_{op}_component')(*args)
        elif typ in {'sbox','linear_layer','mix_column','fsr'}:
            component = getattr(cipher, f'add_{typ}_component')(ids,pos,bits,desc)
        elif typ == 'permutation':
            component = cipher.add_permutation_component(ids,pos,bits,desc[0],desc[1])
        elif typ == 'cipher_output':
            component = cipher.add_cipher_output_component(ids,pos,bits)
        elif typ == 'intermediate_output':
            component = cipher.add_intermediate_output_component(ids,pos,bits,desc[0])
        else:
            raise ValueError(f'Unsupported executable component type: {typ}')
        links[n['id']] = component.id
    while current_round < ir['rounds']-1:
        cipher.add_round(); current_round += 1
    cipher.diagram_source_ids = links
    return cipher


def to_ascii(ir):
    """Lossless, visible ASCII DAG exchange; JSON fields are explicit semantics.

    This first typed dialect is not a legacy glyph-grid layout. The builder's
    typed importer parses these visible records without an embedded graph blob.
    """
    validate(ir)
    header = {k: v for k,v in ir.items() if k not in {'inputs','nodes'}}
    lines = ['+ CLAASP-DIAGRAMS 1 +', '| primitive '+json.dumps(header,sort_keys=True)]
    lines += ['| input '+json.dumps(i,sort_keys=True) for i in ir['inputs']]
    for n in ir['nodes']:
        lines += ['+ node '+json.dumps(n,sort_keys=True)]
    return '\n'.join(lines)+'\n+ END +\n'


def from_ascii(text):
    lines = text.splitlines()
    if not lines or lines[0] != '+ CLAASP-DIAGRAMS 1 +' or lines[-1] != '+ END +':
        raise ValueError('Invalid typed ASCII framing')
    ir = None; inputs = []; nodes = []
    for line in lines[1:-1]:
        if line.startswith('| primitive ') and ir is None: ir = json.loads(line[12:])
        elif line.startswith('| input '): inputs.append(json.loads(line[8:]))
        elif line.startswith('+ node '): nodes.append(json.loads(line[7:]))
        else: raise ValueError('Unknown or duplicate ASCII record')
    if ir is None: raise ValueError('Missing primitive record')
    ir['inputs'] = inputs; ir['nodes'] = nodes
    return validate(ir)


def layout(ir):
    """Deterministic dependency layers; no name-based placement decisions."""
    validate(ir)
    depth = {i['id']: 0 for i in ir['inputs']}; rows = {}
    for n in ir['nodes']:
        depth[n['id']] = 1+max([depth[e['source']] for e in n['operands']] or [0])
    for identity, layer in depth.items(): rows.setdefault(layer, []).append(identity)
    return {identity: {'layer': layer, 'slot': slot} for layer, ids in rows.items() for slot, identity in enumerate(ids)}


def to_tikz(ir, *, layer_spacing=2, slot_spacing=3):
    positions = layout(ir); aliases = {identity: f'n{i}' for i, identity in enumerate(positions)}
    def escape(s):
        return ''.join({'_':r'\_', '%':r'\%', '&':r'\&', '#':r'\#', '{':r'\{', '}':r'\}', '\\':r'\textbackslash{}', '$':r'\$', '^':r'\textasciicircum{}', '~':r'\textasciitilde{}'}.get(c,c) for c in str(s))
    lines = [r'\begin{tikzpicture}[>=stealth, every node/.style={draw,align=center}]']
    for identity,p in positions.items():
        lines.append(fr'\node ({aliases[identity]}) at ({p["slot"]*slot_spacing},{-p["layer"]*layer_spacing}) {{{escape(identity)}}};')
    for n in ir['nodes']:
        for index,e in enumerate(n['operands']):
            label = escape(f'{index}: {e["positions"]}')
            lines.append(fr'\draw[->] ({aliases[e["source"]]}) -- node[draw=none,fill=white,font=\tiny] {{{label}}} ({aliases[n["id"]]});')
    return '\n'.join(lines+[r'\end{tikzpicture}'])


def state_view(ir, *, shape=None):
    """Declared intermediate outputs only; a flat fallback exposes ambiguity."""
    validate(ir)
    stages = []
    for n in ir['nodes']:
        if n['type'] not in {'intermediate_output','cipher_output'}: continue
        positions = [(e['source'],b) for e in n['operands'] for b in e['positions']]
        if shape is not None and (len(shape)!=2 or any(type(x) is not int or x<=0 for x in shape) or shape[0]*shape[1]!=len(positions)):
            raise ValueError('Explicit shape must cover all selected state bits')
        stages.append({'id':n['id'],'round':n['round'],'tag':n['description'],
                       'shape':list(shape) if shape else [1,len(positions)],
                       'geometry':'explicit' if shape else 'ambiguous-flat-fallback', 'ordered_bits':positions})
    return stages
