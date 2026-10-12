"""Recover ordered bit streams from visible glyphs and local definitions."""
import copy
import json
from collections import deque
from claasp.diagram_glyphs import MARKER, SIDES, DELTA, OPPOSITE, _art, _wire_templates

_RECORD_FIELDS = {
    'input': {'kind', 'index', 'id', 'bits', 'role'},
    'native': {'kind', 'ordinal', 'id', 'type', 'bits', 'input_bits', 'round', 'description', 'tag', 'operand_positions'},
    'parallel': {'kind', 'bits', 'tag', 'members'},
    'selection': {'kind', 'bits', 'positions', 'tag'},
    'join': {'kind', 'bits', 'tag'},
}
_MEMBER_FIELDS = {'id', 'type', 'bits', 'input_bits', 'round', 'description', 'ordinal', 'operand_positions'}
_NODE_FIELDS = ('id', 'type', 'bits', 'input_bits', 'round', 'description')


def _members(definition):
    kind = definition.get('kind')
    if kind == 'parallel':
        members = definition.get('members')
        if not isinstance(members, list) or not members:
            raise ValueError('Invalid parallel members')
        return members
    if kind == 'native':
        return [definition]
    return []


def _member_expansion(member):
    if not isinstance(member, dict):
        raise ValueError('Invalid native bit expansion')
    if any(type(member.get(field)) is not int or member[field] < 0 for field in ('bits', 'input_bits')):
        raise ValueError('Invalid native bit expansion')
    return member['bits']+member['input_bits']


def _aggregate_bounds(records):
    native_count, bit_expansion = 0, 0
    for record in records:
        definition = record['definition']
        members = _members(definition)
        native_count += len(members)
        if native_count > 20000:
            raise ValueError('Aggregate native component count exceeds work bound')
        if definition.get('kind') == 'input':
            bit_expansion += definition.get('bits', 2000001)
        bit_expansion += sum(_member_expansion(member) for member in members)
        if bit_expansion > 2000000:
            raise ValueError('Aggregate native explicit bit expansion exceeds bound')


def _record_map(records):
    result = {}
    for record in records:
        key = (record['row'], record['col'])
        definition = record['definition']
        if any(type(value) is not int or value < 0 for value in key):
            raise ValueError('Invalid glyph anchor')
        if type(definition.get('bits')) is not int or not 0 < definition['bits'] <= 2000000:
            raise ValueError('Local bit width exceeds work bound')
        if key in result or set(definition)-_RECORD_FIELDS.get(definition.get('kind'), set()):
            raise ValueError('Duplicate or hidden dependency record')
        result[key] = definition
    return result


def _framing(text, maximum_bytes, maximum_area):
    if len(text.encode('utf8')) > maximum_bytes:
        raise ValueError('Glyph text exceeds max_text_bytes')
    if text.count(MARKER) != 1:
        raise ValueError('Invalid typed glyph framing')
    drawing, footer = text.split(MARKER)
    manifest = json.loads(footer)
    if set(manifest) != {'primitive', 'records'}:
        raise ValueError('Unexpected glyph metadata')
    if len(manifest['records']) > 20000:
        raise ValueError('Glyph definitions exceed work bound')
    _aggregate_bounds(manifest['records'])
    records = _record_map(manifest['records'])
    lines = drawing.split('\n')
    rows, cols = (len(lines)+4)//5, (max(map(len, lines), default=0)+10)//11
    if len(lines) % 5:
        raise ValueError('Glyph line count must be a multiple of five')
    if rows*cols > maximum_area:
        raise ValueError('Glyph grid exceeds max_grid_area')
    return manifest, records, lines, rows, cols


def _cell_art(lines, row, col, cols):
    return tuple(lines[row*5+index].ljust(cols*11)[col*11:(col+1)*11] for index in range(5))


def _input_cell(definition, art):
    return {'kind': 'input', 'ports': {'bottom': 'out'}, 'index': definition['index'],
            'secret': definition['role'] == 'key', 'definition': definition,
            'unindexed': art[2][2:9] == '_______'}


def _operation_cell(definition, art):
    if definition.get('kind') not in ('native', 'parallel', 'selection', 'join'):
        raise ValueError('Unknown local glyph definition')
    if art[2][2:9].strip() != definition.get('tag'):
        raise ValueError('Operation alias disagrees with visible box')
    ports = {'bottom': 'out'}
    for side, marker, line, col in [('top', 'v', 0, 5), ('left', '>', 2, 0), ('right', '<', 2, 10)]:
        if art[line][col] == marker:
            ports[side] = 'in'
    binding = art[1][2:9].strip()
    if binding not in ('', '@21'):
        raise ValueError('Malformed operand binding')
    return {'kind': 'box', 'ports': ports, 'tag': definition['tag'], 'reverse': binding == '@21', 'definition': definition}


def _sink_cell(art, row, col):
    for kind in ('output', 'tap'):
        ports = {'top': 'in'}
        if kind == 'tap':
            ports['bottom'] = 'out'
        candidate = {'kind': kind, 'ports': ports}
        if tuple(_art(candidate)) == art:
            return candidate
    raise ValueError(f'Unknown or malformed glyph at {row}:{col}')


def _defined_cell(definition, art):
    if definition.get('kind') == 'input':
        return _input_cell(definition, art)
    return _operation_cell(definition, art)


def _recognize_cell(key, art, definition, templates, choices):
    if definition:
        cell = _defined_cell(definition, art)
    elif art in templates:
        choices[key] = copy.deepcopy(templates[art])
        cell = choices[key][0]
    else:
        cell = _sink_cell(art, key[0], key[1])
    if tuple(_art(cell)) != art:
        raise ValueError(f'Glyph definition contradicts visible text at {key[0]}:{key[1]}')
    return cell


def _read_cells(records, lines, rows, cols):
    cells, choices = {}, {}
    templates = _wire_templates()
    for row in range(rows):
        for col in range(cols):
            art = _cell_art(lines, row, col, cols)
            if all(not line.strip() for line in art):
                continue
            key = (row, col)
            cells[key] = _recognize_cell(key, art, records.get(key), templates, choices)
    if set(records)-set(cells):
        raise ValueError('Local definition lacks a visible box')
    return cells, choices



def _adjacent(key, side):
    dr, dc = DELTA[side]
    return (key[0]+dr, key[1]+dc), OPPOSITE[side]


def _opposite_direction(direction):
    return 'in' if direction == 'out' else 'out'


def _supported_variant(key, variant, alternatives):
    for side, direction in variant['ports'].items():
        neighbor, opposite = _adjacent(key, side)
        expected = _opposite_direction(direction)
        if not any(cell['ports'].get(opposite) == expected for cell in alternatives.get(neighbor, [])):
            return False
    return True


def _propagate_alternatives(alternatives):
    changed = False
    for key, variants in alternatives.items():
        supported = [variant for variant in variants if _supported_variant(key, variant, alternatives)]
        if not supported:
            raise ValueError(f'Disconnected or reversed port at {key}')
        if len(supported) != len(variants):
            alternatives[key] = supported
            changed = True
    return changed


def _resolved_alternatives(cells, choices):
    alternatives = {key: choices.get(key, [cell]) for key, cell in cells.items()}
    changed = True
    while changed:
        changed = _propagate_alternatives(alternatives)
    for key, variants in alternatives.items():
        if len(variants) != 1:
            raise ValueError(f'Ambiguous wire direction at {key}')
        cells[key] = variants[0]


def _connected_ports(cells):
    for (row, col), cell in cells.items():
        for side, direction in cell['ports'].items():
            neighbor, opposite = _adjacent((row, col), side)
            other = cells.get(neighbor)
            if not other or other['ports'].get(opposite) != _opposite_direction(direction):
                raise ValueError(f'Disconnected or reversed port at {row}:{col}:{side}')


def _box_inputs(cell):
    inputs = [side for side in SIDES if cell['ports'].get(side) == 'in']
    if cell.get('reverse'):
        if len(inputs) != 2:
            raise ValueError('Operand permutation requires two inputs')
        inputs.reverse()
    return inputs


def _incoming_sides(cell, outgoing):
    kind = cell['kind']
    if kind == 'input':
        return []
    if kind == 'box':
        return _box_inputs(cell)
    if kind == 'cross':
        return [{'bottom': 'top', 'right': 'left'}.get(outgoing, 'right')]
    inputs = [side for side, direction in cell['ports'].items() if direction == 'in']
    if len(inputs) != 1:
        raise ValueError('Ambiguous wire source')
    return inputs


def _dependencies(cells):
    dependencies, followers = {}, {}
    for key, cell in cells.items():
        for side, direction in cell['ports'].items():
            if direction != 'out':
                continue
            token = (key, side)
            dependencies[token] = [_adjacent(key, incoming) for incoming in _incoming_sides(cell, side)]
            for dependency in set(dependencies[token]):
                followers.setdefault(dependency, []).append(token)
    return dependencies, followers


def _flat_stream(arguments):
    return [(edge['source'], bit) for incoming in arguments for edge in incoming for bit in edge['positions']]


def _selection(definition, arguments):
    flat = _flat_stream(arguments)
    valid_source = flat and len({source for source, bit in flat}) == 1
    valid_positions = all(type(index) is int and 0 <= index < len(flat) for index in definition['positions'])
    if len(arguments) != 1 or not valid_source or not valid_positions:
        raise ValueError('Invalid visible selection width')
    if len(definition['positions']) != definition['bits']:
        raise ValueError('Selection width mismatch')
    return [{'source': flat[0][0], 'positions': [flat[index][1] for index in definition['positions']]}]


def _join(definition, arguments):
    if len(arguments) != 2:
        raise ValueError('Join needs two ordered inputs')
    stream = [edge for incoming in arguments for edge in incoming]
    if sum(len(edge['positions']) for edge in stream) != definition['bits']:
        raise ValueError('Join width mismatch')
    return stream


def _native_definitions(definition):
    definitions = definition['members'] if definition['kind'] == 'parallel' else [definition]
    if not isinstance(definitions, list) or not definitions or len(definitions) > 20000:
        raise ValueError('Invalid parallel members')
    valid_widths = all(isinstance(item, dict) and type(item.get('bits')) is int
                       and 0 < item['bits'] <= definition['bits'] for item in definitions)
    if not valid_widths:
        raise ValueError('Invalid parallel member width')
    if sum(item['bits'] for item in definitions) != definition['bits']:
        raise ValueError('Parallel output width mismatch')
    return definitions


def _local_operand(positions, flat):
    if not isinstance(positions, list) or not positions or any(type(index) is not int or not 0 <= index < len(flat) for index in positions):
        raise ValueError('Invalid local operand positions')
    selected = [flat[index] for index in positions]
    if len({source for source, bit in selected}) != 1:
        raise ValueError('One native operand must select a single visible value')
    return {'source': selected[0][0], 'positions': [bit for source, bit in selected]}


def _local_operands(definition, arguments, flat):
    if 'operand_positions' not in definition:
        return [edge for incoming in arguments for edge in incoming]
    maps = definition['operand_positions']
    if not isinstance(maps, list):
        raise ValueError('Invalid local operand positions')
    operands = [_local_operand(positions, flat) for positions in maps]
    if sum(len(edge['positions']) for edge in operands) != definition['input_bits']:
        raise ValueError('Local operand positions disagree with input width')
    return operands


def _native_node(definition, group, arguments, flat, native):
    if group['kind'] == 'parallel' and set(definition)-_MEMBER_FIELDS:
        raise ValueError('Hidden dependency in parallel operation')
    node = {key: copy.deepcopy(definition[key]) for key in _NODE_FIELDS}
    node['operands'] = _local_operands(definition, arguments, flat)
    ordinal = definition.get('ordinal')
    if type(ordinal) is not int or ordinal < 0 or ordinal in native:
        raise ValueError('Invalid or duplicate native ordinal')
    native[ordinal] = node
    return {'source': definition['id'], 'positions': list(range(definition['bits']))}


def _native_stream(definition, arguments, native):
    definitions = _native_definitions(definition)
    flat = _flat_stream(arguments)
    stream = [_native_node(member, definition, arguments, flat, native) for member in definitions]
    if sum(len(edge['positions']) for edge in stream) != definition['bits']:
        raise ValueError('Parallel output width mismatch')
    return stream


def _box_stream(definition, arguments, native):
    if definition['kind'] == 'selection':
        return _selection(definition, arguments)
    if definition['kind'] == 'join':
        return _join(definition, arguments)
    return _native_stream(definition, arguments, native)


def _stream(cell, arguments, native):
    definition = cell.get('definition')
    if cell['kind'] == 'input':
        return [{'source': definition['id'], 'positions': list(range(definition['bits']))}]
    if cell['kind'] == 'box':
        return _box_stream(definition, arguments, native)
    return arguments[0]


def _trace_streams(cells):
    dependencies, followers = _dependencies(cells)
    remaining = {token: len(set(values)) for token, values in dependencies.items()}
    ready = deque(token for token, count in remaining.items() if count == 0)
    memo, native = {}, {}
    while ready:
        token = ready.popleft()
        arguments = [memo[dependency] for dependency in dependencies[token]]
        memo[token] = _stream(cells[token[0]], arguments, native)
        for following in followers.get(token, []):
            remaining[following] -= 1
            if not remaining[following]:
                ready.append(following)
    if len(memo) != len(dependencies):
        raise ValueError('Circular visible routing')
    return memo, native


def _observed_definitions(cells, records, memo):
    for key, cell in cells.items():
        if cell['kind'] in ('output', 'tap') and _adjacent(key, 'top') not in memo:
            raise ValueError('Unresolved visible output')
        if key in records and not any((key, side) in memo for side in cell['ports'] if cell['ports'][side] == 'out'):
            raise ValueError('Unobserved annotated operation')


def _execution_order(manifest, records, native):
    inputs = [definition for definition in records.values() if definition.get('kind') == 'input']
    inputs.sort(key=lambda definition: definition['index'])
    if [definition['index'] for definition in inputs] != list(range(len(inputs))):
        raise ValueError('Invalid input ordering')
    if sorted(native) != list(range(len(native))):
        raise ValueError('Missing native execution ordinal')
    return dict(manifest['primitive'], inputs=[{key: definition[key] for key in ('id', 'bits', 'role')} for definition in inputs],
                nodes=[native[index] for index in sorted(native)])


def decode(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    manifest, records, lines, rows, cols = _framing(text, max_text_bytes, max_grid_area)
    cells, choices = _read_cells(records, lines, rows, cols)
    _resolved_alternatives(cells, choices)
    _connected_ports(cells)
    memo, native = _trace_streams(cells)
    _observed_definitions(cells, records, memo)
    return _execution_order(manifest, records, native)
