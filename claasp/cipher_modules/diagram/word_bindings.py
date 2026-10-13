"""Private coordinate-local binding experiment for the persistent-word view.

This experimental bridge is separate from the public decoder. Metadata supplies local
widths, identities, rounds and observation names; connectivity is always parsed
from the unchanged body. It contains no operation operand/source links.
"""
import copy
import json
from . import word_visual, glyphs
from .validation import validate, validate_native_component


def export_bindings(ir, *, key_side='right'):
    # A transparent observation cannot secretly become a computational alias.
    # Such nodes need a future actual-route alias annotation, not source repair.
    observed_ids = {node['id'] for node in ir['nodes'] if node['type'] == 'intermediate_output'}
    if any(edge['source'] in observed_ids for node in ir['nodes'] for edge in node['operands']):
        raise ValueError('Consumed observation aliases need explicit route-local flow bindings')
    model = word_visual.build(ir, key_side=key_side)
    body = word_visual.render(model)
    parsed = word_visual.parse(body)
    fields = ('id', 'type', 'bits', 'input_bits', 'round', 'description')
    origins = {token: [0, column] for column, token in enumerate(model['primary'])}
    locals_ = []
    for record in model['records']:
        definition = record['definition']
        key = [record['row'], record['column']]
        # Token identity is used only while exporting local coordinate records.
        candidates = model['constants'] if record['kind'] == 'constant' else model['operations']
        matches = [token for token, value in candidates.items()
                   if (value if record['kind'] == 'constant' else value['definition'])['ordinal'] == definition['ordinal']]
        if len(matches) != 1:
            raise ValueError('Fragmented native groups need a separate bridge contract')
        origins[matches[0]] = key
        locals_.append({'at': key, 'definition': {field: copy.deepcopy(definition[field]) for field in fields},
                        'ordinal': definition['ordinal'], 'operand_ports': copy.deepcopy(definition.get('operand_ports', [])),
                        'operand_positions': copy.deepcopy(definition['operand_positions'])})
    observations = []
    for observation in model['observations']:
        definition = observation['definition']
        observations.append({'definition': {field: copy.deepcopy(definition[field]) for field in fields},
                             'ordinal': definition['ordinal'], 'positions': definition['positions'],
                             'operand_positions': copy.deepcopy(definition['operand_positions']), 'flow': 'observe',
                             'at': [origins[token] for token in observation['words']]})
    final = next(node for node in reversed(ir['nodes']) if node['type'] == 'cipher_output')
    masks, offset = [], 0
    for edge in final['operands']:
        masks.append(list(range(offset, offset+len(edge['positions'])))); offset += len(edge['positions'])
    bindings = {'schema': 'claasp-word-view-bindings/experimental-2', 'word_bits': model['bits'],
                'header': {key: copy.deepcopy(value) for key, value in ir.items() if key not in ('inputs', 'nodes')},
                'native_inputs': copy.deepcopy(ir['inputs']),
                'inputs': [{'at': list(key), 'binding': copy.deepcopy(binding)}
                           for key, binding in zip(parsed['inputs'], model['input_bindings'])],
                'operations': locals_, 'observations': observations,
                'cipher_output': {'definition': {field: copy.deepcopy(final[field]) for field in fields},
                                  'at': [[model['rows']-1, column] for column in model['cipher_columns']],
                                  'ordinal': ir['nodes'].index(final), 'operand_positions': masks},
                'display_terminals': [{'at': list(key), 'cipher': key[1] in model['cipher_columns']}
                                      for key in parsed['outputs']]}
    return body, bindings


def trace_bindings(body, bindings):
    """Expose actual routed producers with distinct cipher/display/observer bindings.

    Tracing alone does not claim exact native reconstruction. decode_bindings
    separately validates and reconstructs supported observe-only native boundaries.
    """
    if bindings.get('schema') != 'claasp-word-view-bindings/experimental-2':
        raise ValueError('Unsupported experimental word binding schema')
    required = {'schema', 'word_bits', 'header', 'native_inputs', 'inputs', 'operations', 'observations', 'cipher_output', 'display_terminals'}
    if set(bindings) != required:
        raise ValueError('Unexpected or missing binding metadata field')
    for record in bindings['operations']:
        if set(record) != {'at', 'definition', 'ordinal', 'operand_ports', 'operand_positions'}:
            raise ValueError('Unexpected operation metadata field; source links are forbidden')
        if set(record['definition']) != set(word_visual.manual_blocks.NODE_FIELDS):
            raise ValueError('Unexpected native definition field; source links are forbidden')
    if set(bindings['header']) != {'schema', 'name', 'cipher_type', 'output_bits', 'rounds'}:
        raise ValueError('Unexpected native header metadata field')
    if any(set(native) != {'id', 'bits', 'role'} for native in bindings['native_inputs']):
        raise ValueError('Unexpected native input declaration field')
    for record in bindings['inputs']:
        if set(record) != {'at', 'binding'} or set(record['binding']) != {'id', 'bits', 'role', 'kind', 'index', 'native_index', 'positions'}:
            raise ValueError('Unexpected input binding metadata field')
        if record['binding']['kind'] != 'input':
            raise ValueError('Input metadata binding is not an input')
    fields = set(word_visual.manual_blocks.NODE_FIELDS)
    for record in bindings['observations']:
        if set(record) != {'definition', 'ordinal', 'positions', 'operand_positions', 'flow', 'at'} or set(record['definition']) != fields:
            raise ValueError('Unexpected observation metadata field; source links are forbidden')
    if set(bindings['cipher_output']) != {'definition', 'at', 'ordinal', 'operand_positions'} or set(bindings['cipher_output']['definition']) != fields:
        raise ValueError('Unexpected cipher output metadata field; source links are forbidden')
    parsed = word_visual.parse(body)
    coordinates = lambda values: [tuple(value) for value in values]
    inputs = coordinates(record['at'] for record in bindings['inputs'])
    if inputs != parsed['inputs']:
        raise ValueError('Input bindings disagree with actual visible endpoints')
    operation_coordinates = [tuple(record['at']) for record in bindings['operations']]
    if len(set(operation_coordinates)) != len(operation_coordinates):
        raise ValueError('Duplicate operation coordinate ownership')
    operations = {tuple(record['at']): record for record in bindings['operations']}
    actual = {key for key, cell in parsed['cells'].items() if cell['kind'] == 'operation'}
    if set(operations) != actual:
        raise ValueError('Local operation annotations do not cover actual glyphs exactly')
    cipher = coordinates(bindings['cipher_output']['at'])
    display = coordinates(record['at'] for record in bindings['display_terminals'])
    if display != parsed['outputs'] or len(set(cipher)) != len(cipher) or any(key not in display for key in cipher):
        raise ValueError('Cipher/display terminal bindings disagree with visible terminals')
    bits = bindings['word_bits']
    if type(bits) is not int or bits <= 0 or len(cipher)*bits != bindings['cipher_output']['definition']['bits']:
        raise ValueError('Cipher width disagrees with its selected actual terminal words')
    if any(record['cipher'] != (tuple(record['at']) in cipher) for record in bindings['display_terminals']):
        raise ValueError('Display terminal roles disagree with explicit cipher endpoint binding')
    operation_sources = {}
    # Cardinalities of explicit local fragments bound numeric declarations before
    # any width-derived allocation or native transform validation.
    if any(not isinstance(record['binding'].get('positions'), list) or len(record['binding']['positions']) != bits
           for record in bindings['inputs']):
        raise ValueError('Word width exceeds actual input fragment cardinality')
    for native_index, native in enumerate(bindings['native_inputs']):
        count = sum(len(record['binding']['positions']) for record in bindings['inputs']
                    if record['binding']['native_index'] == native_index)
        if type(native['bits']) is not int or native['bits'] <= 0 or native['bits'] != count:
            raise ValueError('Native input width disagrees with actual fragment coverage cardinality')
    observation_groups = {}
    for record in bindings['observations']:
        observation_groups.setdefault(record['ordinal'], []).append(record)
    for records in observation_groups.values():
        definition = records[0]['definition']
        count = sum(len(record['positions']) for record in records)
        if type(definition['bits']) is not int or definition['bits'] <= 0 or definition['bits'] != count or definition['input_bits'] != count:
            raise ValueError('Observation width disagrees with actual fragment coverage cardinality')
    rounds = bindings['header']['rounds']
    if type(rounds) is not int or rounds <= 0 or rounds > len(operations)+len(observation_groups)+1:
        raise ValueError('Declared rounds exceed explicit native record capacity')
    for key, record in operations.items():
        definition = record['definition']
        if definition['type'] not in ('word_operation', 'constant') or definition['bits'] != bits:
            raise ValueError('Local operation type/width is unsupported by actual word glyph')
        validate_native_component(definition)
        cell = parsed['cells'][key]
        ordered = [side for side in glyphs.SIDES if side in cell['ports'] and side != 'bottom']
        if cell['binding'].startswith('@'):
            ordered = [ordered[int(value)-1] for value in cell['binding'][1:]]
        declared = record['operand_ports']
        if len(declared) != len(ordered) or sorted(declared) != sorted(ordered):
            raise ValueError('Local ordered port binding disagrees with actual visible ports')
        if cell['binding'] and declared != ordered:
            raise ValueError('Local ordered port binding contradicts visible operand binding')
        by_port = dict(zip(ordered, parsed['sources'][key]))
        operation_sources[key] = [by_port[port] for port in declared]
        local = dict(definition, kind='native', operand_ports=declared)
        art = word_visual._art({'kind': 'box', 'definition': local,
                               'ports': {side: ('out' if side == 'bottom' else 'in') for side in cell['ports']}})
        if cell['label'] != art[2][2:9].strip() or cell['binding'] != art[1][2:9].strip():
            raise ValueError('Native operation metadata contradicts actual visible glyph')
        if definition['bits'] != bits or definition['input_bits'] != len(parsed['sources'][key])*bits:
            raise ValueError('Native operation width contradicts actual word ports')
    observations = []
    for record in bindings['observations']:
        anchors = coordinates(record['at'])
        if any(key not in actual and key not in inputs for key in anchors):
            raise ValueError('Observation anchor is not an actual visible producer')
        if len(anchors)*bindings['word_bits'] != len(record['positions']):
            raise ValueError('Observation widths disagree with actual word anchors')
        observations.append(dict(record, at=anchors))
    return {'operation_sources': operation_sources,
            'cipher_sources': [parsed['sources'][key][0] for key in cipher],
            'display_sources': [parsed['sources'][key][0] for key in display],
            'observations': observations, 'exact_native_reconstruction': False}


def _observation_slots(width, covered):
    # Keep the capacity check at the allocation boundary as well as framing.
    if type(width) is not int or width <= 0 or width != covered:
        raise ValueError('Observation allocation exceeds explicit fragment capacity')
    return [None]*covered


def decode_bindings(body, bindings):
    """Reconstruct supported native IR from actual pixel routes and local bindings.

    Observe-only boundaries are retained with their native identity and round.
    Consumed aliases are explicitly unsupported, never inferred from expected IR.
    """
    trace = trace_bindings(body, bindings)
    parsed = word_visual.parse(body)
    bits = bindings['word_bits']
    atoms = {}
    coverage = {item['id']: [] for item in bindings['native_inputs']}
    for record in bindings['inputs']:
        binding = record['binding']; key = tuple(record['at'])
        index = binding['native_index']
        if type(index) is not int or not 0 <= index < len(bindings['native_inputs']):
            raise ValueError('Invalid packed native input binding')
        native = bindings['native_inputs'][index]
        if any(binding[field] != native[field] for field in ('id', 'bits', 'role')):
            raise ValueError('Packed input binding contradicts native interface')
        if parsed['cells'][key]['secret'] != (native['role'] == 'key'):
            raise ValueError('Secret glyph contradicts native input role')
        positions = binding['positions']
        if len(positions) != bits or any(type(bit) is not int or not 0 <= bit < native['bits'] for bit in positions):
            raise ValueError('Invalid packed input word positions')
        atoms[key] = [(native['id'], bit) for bit in positions]
        coverage[native['id']].extend(positions)
    if any(len(coverage[item['id']]) != item['bits'] or any(bit != index for index, bit in enumerate(sorted(coverage[item['id']]))) for item in bindings['native_inputs']):
        raise ValueError('Packed input words must cover each original bit exactly once')
    operation_coordinates = [tuple(record['at']) for record in bindings['operations']]
    if len(set(operation_coordinates)) != len(operation_coordinates):
        raise ValueError('Duplicate operation coordinate ownership')
    operations = {tuple(record['at']): record for record in bindings['operations']}
    def stream(key):
        if key in atoms:
            return atoms[key]
        if key not in operations:
            raise ValueError('Actual stream does not terminate at an annotated producer')
        definition = operations[key]['definition']
        atoms[key] = [(definition['id'], bit) for bit in range(bits)]
        return atoms[key]
    def pack(flat, masks, width):
        if (not isinstance(masks, list) or any(not isinstance(mask, list) or not mask for mask in masks)
                or len(flat) != width
                or any(bit != index for index, bit in enumerate([bit for mask in masks for bit in mask]))
                or sum(map(len, masks)) != len(flat)):
            raise ValueError('Original edge masks must partition the exact ordered actual stream')
        edges = []
        for mask in masks:
            selected = [flat[index] for index in mask]
            sources = {source for source, bit in selected}
            if len(sources) != 1:
                raise ValueError('One original edge mask conceals multiple actual sources')
            edges.append({'source': selected[0][0], 'positions': [bit for source, bit in selected]})
        return edges
    nodes = {}
    for key, record in operations.items():
        definition = copy.deepcopy(record['definition'])
        flat = [atom for source in trace['operation_sources'][key] for atom in stream(source)]
        definition['operands'] = pack(flat, record['operand_positions'], definition['input_bits'])
        ordinal = record['ordinal']
        if type(ordinal) is not int or ordinal in nodes:
            raise ValueError('Duplicate or invalid native operation ordinal')
        nodes[ordinal] = definition
    groups = {}
    for record in trace['observations']:
        if record.get('flow') != 'observe':
            raise ValueError('Consumed observation aliases need explicit route-local flow bindings')
        groups.setdefault(record['ordinal'], []).append(record)
    for ordinal, records in groups.items():
        first = records[0]
        definition = copy.deepcopy(first['definition'])
        if ordinal in nodes or definition['type'] != 'intermediate_output':
            raise ValueError('Invalid or colliding native observation')
        if definition['bits'] != sum(len(record['positions']) for record in records):
            raise ValueError('Observation allocation exceeds explicit fragment capacity')
        flat = _observation_slots(definition['bits'], sum(len(record['positions']) for record in records))
        for record in records:
            if record['definition'] != definition or record['operand_positions'] != first['operand_positions']:
                raise ValueError('Observation fragments disagree about local native definition')
            incoming = [atom for anchor in record['at'] for atom in stream(anchor)]
            for position, atom in zip(record['positions'], incoming):
                if type(position) is not int or not 0 <= position < len(flat) or flat[position] is not None:
                    raise ValueError('Observation fragments overlap or select invalid positions')
                flat[position] = atom
        if any(atom is None for atom in flat):
            raise ValueError('Observation fragments omit actual native bits')
        definition['operands'] = pack(flat, first['operand_positions'], definition['input_bits'])
        nodes[ordinal] = definition
    output = bindings['cipher_output']
    definition = copy.deepcopy(output['definition'])
    if definition['type'] != 'cipher_output' or output['ordinal'] in nodes:
        raise ValueError('Invalid or colliding native cipher output')
    flat = [atom for source in trace['cipher_sources'] for atom in stream(source)]
    definition['operands'] = pack(flat, output['operand_positions'], definition['input_bits'])
    nodes[output['ordinal']] = definition
    if sorted(nodes) != list(range(len(nodes))):
        raise ValueError('Local records must cover every original native ordinal')
    result = copy.deepcopy(bindings['header'])
    result.update(inputs=copy.deepcopy(bindings['native_inputs']), nodes=[nodes[index] for index in sorted(nodes)])
    return validate(result)


MARKER = '\n# CLAASP-WORD-VIEW-BINDINGS experimental-2\n'


def encode(ir, *, key_side='right'):
    """Private annotated text; ordinary body stays byte-identical."""
    body, bindings = export_bindings(ir, key_side=key_side)
    return body+MARKER+json.dumps(bindings, sort_keys=True, separators=(',', ':'))+'\n'


def decode(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    """Private bounded bridge, deliberately separate from public from_ascii."""
    if not isinstance(text, str) or any(type(value) is not int or value <= 0 for value in (max_text_bytes, max_grid_area)):
        raise ValueError('Invalid bridge text or work bounds')
    if len(text.encode('utf8')) > max_text_bytes:
        raise ValueError('Bridge text exceeds max_text_bytes')
    if text.count(MARKER) != 1:
        raise ValueError('Require exactly one experimental binding section')
    body, metadata = text.split(MARKER)
    lines = body.splitlines()
    if len(lines)*((max(map(len, lines), default=0)+10)//11) > max_grid_area*5:
        raise ValueError('Bridge body exceeds max_grid_area')
    return decode_bindings(body, json.loads(metadata))
