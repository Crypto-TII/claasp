"""Experimental persistent-word view, separate from typed interchange glyphs.

Only proven aligned word aliases are transparent. This prototype does not
guess mixed-width selections, project carries, or dispatch by primitive name.
"""
from collections import Counter
import hashlib
import json

from . import glyphs, manual_blocks
from .validation import validate


class UnsupportedProjection(ValueError):
    """The validated graph needs a different explicit visual representation."""
    pass


def project(ir, word_bits=None, *, max_calls=20000, max_cells=1000000, routed_words=False):
    validate(ir)
    if type(routed_words) is not bool:
        raise ValueError('routed_words must be a boolean')
    if len(ir['nodes']) > max_calls:
        raise ValueError('Native calls exceed max_calls')
    bits = manual_blocks.infer_word_bits(ir) if word_bits is None else word_bits
    if type(bits) is not int or bits <= 0 or any(i['bits'] % bits for i in ir['inputs']):
        raise UnsupportedProjection('Word alignment is ambiguous; a width-aware projection is required')
    if sum(item['bits']//bits for item in ir['inputs']) > max_cells:
        raise ValueError('Input word cells exceed max_cells before projection')
    graph = manual_blocks._WordGraph(ir, bits)
    if len(graph.calls) > max_calls:
        raise ValueError('Projected calls exceed max_calls')
    words = {value: [value] for value in graph.inputs}
    operations, constants, observations = {}, {}, []
    for index, call in enumerate(graph.calls):
        token = ('call', index)
        definition = call['definition']
        args = [part for value in call['args'] for part in words[value]]
        kind = definition['kind']
        if kind == 'join':
            words[token] = args
        elif kind == 'selection':
            selected = []
            positions = definition['positions']
            for start in range(0, len(positions), bits):
                chunk = positions[start:start+bits]
                if len(chunk) != bits or chunk != list(range(chunk[0]//bits*bits, chunk[0]//bits*bits+bits)):
                    raise UnsupportedProjection('A non-word-aligned selection needs genuine bit routing')
                selected.append(args[chunk[0]//bits])
            words[token] = selected
        elif kind == 'native_boundary':
            words[token] = args
            if definition['type'] == 'intermediate_output':
                observations.append({'definition': definition, 'words': args})
        else:
            if call['bits'] != bits or definition['bits'] != bits:
                raise UnsupportedProjection('Mixed-width operation ports need a width-aware visual projection')
            if definition['type'] == 'constant':
                constants[token] = definition
            elif definition['type'] == 'word_operation' and (len(args) <= 2 or
                    routed_words and len(args) == 3 and definition['description'][0] in ('XOR', 'AND', 'OR')):
                operations[token] = dict(call, args=args)
            else:
                raise UnsupportedProjection('This operation needs a genuine multi-port or permutation projection')
            words[token] = [token]
    final = next(node for node in reversed(ir['nodes']) if node['type'] == 'cipher_output')
    outputs = [part for value in graph.values[final['id']] for part in words[value]]
    return {'bits': bits, 'inputs': graph.inputs, 'input_definitions': graph.input_definitions,
            'operations': operations, 'constants': constants, 'outputs': outputs,
            'observations': observations}



def _downstream_contexts(operations, outputs, signatures):
    """Hash dependency/output context without identifiers or declaration order.

    Upstream-identical operations can feed different consumers. Their argument
    positions, consumer structures and ordered cipher words resolve a scheduling
    tie reproducibly. Digests keep context size linear rather than expanding a
    recursive expression string. Fully symmetric unused nodes retain the final
    stable declaration-index tie-break; their physical glyphs are identical.
    """
    uses, endpoints = {}, {}
    for consumer, call in operations.items():
        for index, argument in enumerate(call['args']):
            uses.setdefault(argument, []).append((consumer, index))
    for index, value in enumerate(outputs):
        endpoints.setdefault(value, []).append(('output', index))
    contexts = {}
    for value in reversed(list(operations)):
        terms = list(endpoints.get(value, []))
        terms.extend(('use', index, signatures[consumer], contexts[consumer])
                     for consumer, index in uses.get(value, []))
        terms.sort(key=lambda term: json.dumps(term, sort_keys=True))
        contexts[value] = hashlib.sha256(json.dumps(terms).encode()).hexdigest()
    return contexts

def build(ir, *, key_side='right', word_bits=None, max_calls=20000, max_cells=1000000,
          max_grid_area=2000000, capture_states=False, parallel_unary=1, routed_words=False):
    r"""
    Infer a persistent word-state layout from native dependencies and roles.

    INPUT:

    - ``ir`` -- **dictionary**; validated native graph
    - ``key_side`` -- **string** (default: ``'right'``); ``'right'`` or ``'left'`` generic key-bank placement
    - ``word_bits`` -- positive **integer** or ``None`` (default); explicit or inferred admitted word width
    - ``max_calls`` -- positive **integer** (default: ``20000``); native/projected operation limit
    - ``max_cells`` -- positive **integer** (default: ``1000000``); occupied-cell limit
    - ``max_grid_area`` -- positive **integer** (default: ``2000000``); rectangular-grid limit
    - ``routed_words`` -- **boolean** (default: ``False``); explicit uniform-word fan-out/temporary
      routing, three-port XOR/AND/OR and native output selection from actual visible terminals. Native
      cipher order is labelled C0,C1,... in TikZ; D marks carried display values. Local annotations are
      required for native packing in ASCII. Widths, ordered masks and actual sources remain checked.
    - ``parallel_unary`` -- positive **integer** (default: ``1``); maximum compatible independent
      unary operations coalesced per row after the dependency-aware route schedule;1preserves existing bytes
    - ``capture_states`` -- **boolean** (default: ``False``); record initial/every-operation primary lane banks;
      constants are parameters, not state updates

    These limits do not constrain the requested width/depth of a layout. Lane count and operation rows
    follow the generic dependency/liveness schedule; no width/depth preference or cipher template is used.

    OUTPUT:

    A **dictionary** containing actual cells, native input bindings and explicit
    cipher endpoint columns. Other primary terminals carry display state. ``state_frames`` is empty
    unless capture is requested; captured frames retain actual native producer-bit positions and roles,
    including unchanged primary lanes while a temporary result resides in an auxiliary lane.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: from claasp.cipher_modules.diagram.word_visual import build
        sage: model = build(from_cipher(SpeckBlockCipher(number_of_rounds=int(1))))
        sage: (model['bits'], model['columns'], len(model['cipher_columns']))
        (16, 6, 2)
    """
    if type(routed_words) is not bool:
        raise ValueError('routed_words must be a boolean')
    if type(parallel_unary) is not int or parallel_unary < 1:
        raise ValueError('parallel_unary must be a positive integer')
    if key_side not in ('right', 'left'):
        raise ValueError('Choose key_side right or left')
    model = project(ir, word_bits, max_calls=max_calls, max_cells=max_cells, routed_words=routed_words)
    ops, constants = model['operations'], model['constants']
    if len(ops)+len(constants) > max_calls:
        raise ValueError('Visual operations exceed max_calls')
    roles = {value: ('key' if model['input_definitions'][value[1]]['role'] == 'key' else 'data') for value in model['inputs']}
    signatures = {value: ('input', model['input_definitions'][value[1]]['native_index'], tuple(model['input_definitions'][value[1]]['positions'])) for value in model['inputs']}
    births = {value: -1 for value in model['inputs']}
    for value, definition in constants.items():
        roles[value] = 'neutral'
        signatures[value] = ('constant', definition['bits'], definition['description'][0])
    for value, call in ops.items():
        inherited = {roles[arg] for arg in call['args']} - {'neutral'}
        roles[value] = 'key' if inherited == {'key'} else 'data'
        facts = (call['definition']['round'], call['definition']['description'], [signatures[arg] for arg in call['args']])
        signatures[value] = hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()
    duplicate_signatures = Counter(signatures[value] for value in ops)
    contexts = _downstream_contexts(ops, model['outputs'], signatures) if routed_words else {}
    consumers = {value: [] for value in roles}
    for value, call in ops.items():
        for arg in call['args']:
            consumers[arg].append(value)
    critical = {}
    for value in reversed(list(ops)):
        critical[value] = 1+max((critical[consumer] for consumer in consumers[value]), default=0)
    def first_use(value):
        return min((ops[c]['definition']['round'] for c in consumers[value]), default=10**9), value[1]
    data = [v for v in model['inputs'] if roles[v] == 'data']
    keys = sorted((v for v in model['inputs'] if roles[v] == 'key'), key=first_use)
    primary = data+keys if key_side == 'right' else keys+data
    if len(model['outputs']) != len(data):
        raise UnsupportedProjection('Cipher word outputs and data-state lanes have unequal shape')
    homes = {value: column for column, value in enumerate(primary)}
    state = {column: value for value, column in homes.items()}
    available = set(model['inputs']) | set(constants)
    remaining = Counter(arg for call in ops.values() for arg in call['args'])
    remaining.update(model['outputs'])
    cells, records, row = {}, [], 0
    extent = len(primary)
    if type(capture_states) is not bool:
        raise ValueError('capture_states must be a boolean')
    state_frames = []
    for column, value in enumerate(primary):
        definition = model['input_definitions'][value[1]]
        cells[(0, column)] = {'kind': 'input', 'ports': {'bottom': 'out'}, 'unindexed': True,
                              'secret': roles[value] == 'key'}
    def record_state(stage, operation=None):
        if not capture_states:
            return
        snapshot = []
        for column, initial in enumerate(primary):
            value = state[column]
            if value[0] == 'input':
                definition = model['input_definitions'][value[1]]
                positions = [(definition['id'], bit) for bit in definition['positions']]
            else:
                definition = ops[value]['definition'] if value in ops else constants[value]
                positions = [(definition['id'], bit) for bit in range(model['bits'])]
            snapshot.append({'column': column, 'role': roles[initial], 'positions': positions})
        state_frames.append({'stage': stage, 'operation': operation, 'words': snapshot})
    record_state(-1)
    def vertical():
        return {column: {'kind': 'wire', 'ports': {'top': 'in', 'bottom': 'out'}, 'invisible': True} for column in state}
    def append(line):
        nonlocal row, extent
        if routed_words:
            if len(cells)+len(line) > max_cells:
                raise ValueError('Visual cells exceed max_cells before routed-row allocation')
            extent = max(extent, max(line, default=-1)+1)
            if (row+2)*extent > max_grid_area:
                raise ValueError('Visual grid bound exceeded before routed-row allocation')
        row += 1
        cells.update({(row, column): cell for column, cell in line.items()})
    def location(value):
        return next(column for column, current in state.items() if current == value)
    def auxiliary(after=-1):
        capacity = len(primary)+len(ops)*(3 if routed_words else 1)+len(constants)+(3 if routed_words else 2)
        column = next((column for column in range(max(len(primary), after+1), capacity) if column not in state), None)
        if column is None:
            raise UnsupportedProjection('Bounded temporary-lane capacity cannot route this word graph')
        return column
    def constant(value):
        if value in state.values():
            return
        column = auxiliary()
        line = vertical()
        definition = constants[value]
        line[column] = {'kind': 'box', 'ports': {'bottom': 'out'}, 'definition': definition, 'tag': 'constant'}
        append(line)
        state[column] = value
        births[value] = row
        records.append({'row': row, 'column': column, 'kind': 'constant', 'definition': definition})
    def horizontal(line, source, destination, keep_source):
        direction = 'right' if destination > source else 'left'
        ports = {'top': 'in', direction: 'out'}
        if keep_source:
            ports['bottom'] = 'out'
        line[source] = {'kind': 'fork' if keep_source else 'wire', 'ports': ports, 'invisible': True}
        for column in range(min(source, destination)+1, max(source, destination)):
            ports = {'left': 'in', 'right': 'out'}
            if column in state:
                ports.update(top='in', bottom='out')
            line[column] = {'kind': 'cross' if column in state else 'wire', 'ports': ports, 'invisible': True}
    def copy_word(value, after=-1):
        source, destination = location(value), auxiliary(after)
        line = vertical()
        horizontal(line, source, destination, True)
        side = 'left' if source < destination else 'right'
        line[destination] = {'kind': 'wire', 'ports': {side: 'in', 'bottom': 'out'}, 'invisible': True}
        append(line)
        state[destination] = value
        return destination
    pending = set(ops)
    while pending:
        ready = [value for value in pending if all(arg in available for arg in ops[value]['args'])]
        if not ready:
            raise ValueError('Visual operation graph is cyclic or disconnected')
        def score(value):
            call = ops[value]
            anchors = [homes[arg] for arg in call['args'] if arg in homes]
            priority = (call['definition']['round'], roles[value] != 'key', -critical[value],
                        -max((births.get(arg, -1) for arg in call['args']), default=-1),
                        min(anchors, default=10**9), str(signatures[value]))
            if routed_words and duplicate_signatures[signatures[value]] > 1:
                return priority+(contexts[value], value[1])
            return priority
        value = min(ready, key=score)
        call = ops[value]
        for arg in call['args']:
            if arg in constants:
                constant(arg)
        args = list(call['args'])
        for arg in args:
            remaining[arg] -= 1
        candidates = [arg for arg in args if roles[arg] == roles[value] and remaining[arg] == 0]
        if candidates:
            selected = max(candidates, key=lambda arg: (births.get(arg, -1), -location(arg)))
            destination = location(selected)
        else:
            if not routed_words:
                raise UnsupportedProjection('A live-operand spill needs an explicit wire-preserving placement')
            destination = copy_word(args[0])
        argument_columns = [location(arg) for arg in args]
        if routed_words:
            # Pin one actual argument above the operation. A ternary Boolean
            # gate needs one distinct stream on each horizontal side; fork
            # copies create those streams without adding semantic operations.
            if len(args) == 3:
                destination = copy_word(args[0], after=max(state))
                argument_columns = [destination, location(args[1]), copy_word(args[2], after=max(state))]
            else:
                if destination not in argument_columns:
                    argument_columns[0] = destination
                for index in range(1, len(args)):
                    if argument_columns[index] in argument_columns[:index]:
                        argument_columns[index] = copy_word(args[index])
        if not routed_words and len(args) == 2 and args[0] == args[1]:
            duplicate = auxiliary()
            source = argument_columns[0]
            line = vertical()
            horizontal(line, source, duplicate, True)
            side = 'left' if source < duplicate else 'right'
            line[duplicate] = {'kind': 'wire', 'ports': {side: 'in', 'bottom': 'out'}, 'invisible': True}
            append(line)
            state[duplicate] = args[0]
            argument_columns[1] = duplicate
        if destination not in argument_columns:
            raise UnsupportedProjection('Operation needs an explicit incoming wire route')
        line = vertical()
        ports = {'top': 'in', 'bottom': 'out'}
        ordered = []
        for arg, source in zip(args, argument_columns):
            if source == destination:
                ordered.append('top')
            else:
                side = 'left' if source < destination else 'right'
                ports[side] = 'in'
                ordered.append(side)
                keep = source < len(primary) or remaining[arg] > 0
                horizontal(line, source, destination, keep)
                if not keep:
                    del state[source]
        definition = dict(call['definition'], operand_ports=ordered)
        line[destination] = {'kind': 'box', 'ports': ports, 'definition': definition, 'tag': 'operation'}
        append(line)
        state[destination] = value
        homes[value] = destination
        births[value] = row
        available.add(value)
        pending.remove(value)
        records.append({'row': row, 'column': destination, 'kind': 'operation', 'definition': definition})
        record_state(definition['round'], definition['id'])
    data_columns = [homes[value] for value in data]
    if routed_words:
        data_columns = []
        for value in model['outputs']:
            matches = [column for column in state if state[column] == value and column not in data_columns]
            data_columns.append(matches[0] if matches else copy_word(value))
        final_columns = sorted(state)
    else:
        if [state[column] for column in data_columns] != model['outputs']:
            raise UnsupportedProjection('Final output ordering needs an explicit permutation wire route')
        final_columns = range(len(primary))
    final_row = {column: {'kind': 'output', 'ports': {'top': 'in'}, 'unindexed': True} for column in final_columns}
    if routed_words:
        for column, cell in final_row.items():
            cell['endpoint_label'] = 'C'+str(data_columns.index(column)) if column in data_columns else 'D'
    append(final_row)
    columns = max(column for _, column in cells)+1
    if (row+1)*columns > max_grid_area:
        raise ValueError('Visual grid bound exceeded')
    if len(cells) > max_cells:
        raise ValueError('Visual cells exceed max_cells')
    model.update(primary=primary, input_bindings=[model['input_definitions'][value[1]] for value in primary],
                 cipher_columns=data_columns, records=records, cells=cells, rows=row+1, columns=columns,
                 key_side=key_side, state_frames=state_frames)
    from .compact_unary import compact
    return compact(model, parallel_unary)


def _art(cell):
    if cell['kind'] != 'box':
        return glyphs._art(cell)
    definition = cell['definition']
    local = dict(cell, reverse=False)
    result = manual_blocks.art(local)
    if definition['type'] == 'constant':
        text = 'x'+format(int(definition['description'][0], 0), '02X')
        result[2] = ' |'+glyphs._center(text)+'| '
    elif definition['description'][0] == 'MODSUB':
        physical = [side for side in glyphs.SIDES if cell['ports'].get(side) == 'in']
        binding = [physical.index(side)+1 for side in definition['operand_ports']]
        if binding != list(range(1, len(binding)+1)):
            result[1] = ' |'+glyphs._center('@'+''.join(map(str, binding)))+'| '
    return result


def render(model):
    blank = [' '*11]*5
    lines = []
    for row in range(model['rows']):
        parts = [_art(model['cells'][(row, column)]) if (row, column) in model['cells'] else blank for column in range(model['columns'])]
        lines.extend(''.join(part[index] for part in parts) for index in range(5))
    return '\n'.join(lines)+'\n'


def to_ascii(ir, **options):
    r"""
    Render the admitted word-state view using actual manual glyphs and routes.

    INPUT:

    - ``ir`` -- **dictionary**; native graph
    - ``options`` -- keyword controls accepted by ``build``

    OUTPUT:

    A plain ASCII **string**; native widths and interface packing require the
    separate annotated bridge. No primitive name chooses a layout.
    """
    return render(build(ir, **options))


def parse(text):
    """Read actual glyphs/wires; no original graph or generated calls are used."""
    lines = text.replace('\r\n', '\n').splitlines()
    if not lines or len(lines) % 5:
        raise ValueError('Visual diagram requires complete five-line rows')
    columns = (max(map(len, lines))+10)//11
    cells = {}
    for row in range(len(lines)//5):
        for column in range(columns):
            art = tuple(line.ljust(columns*11)[column*11:(column+1)*11] for line in lines[row*5:row*5+5])
            if not any(line.strip() for line in art):
                continue
            middle = art[2]
            ports = set()
            if art[0][5] in ('|', 'v'):
                ports.add('top')
            if art[4][5] == '|':
                ports.add('bottom')
            if middle[0] in ('-', '>', '<'):
                ports.add('left')
            if middle[10] in ('-', '>', '<'):
                ports.add('right')
            if middle[2:9] == '_______':
                kind = 'input' if ports == {'bottom'} else 'output' if ports == {'top'} else None
                if kind is None:
                    raise ValueError('Invalid visual endpoint')
                cell = {'kind': kind, 'ports': ports, 'secret': middle[1] == 'S'}
            elif art[3][1:10] == '|_______|' and middle[1] == '|' and middle[9] == '|':
                cell = {'kind': 'operation', 'ports': ports, 'label': middle[2:9].strip(), 'binding': art[1][2:9].strip()}
            else:
                marker = middle[5]
                if marker == 'o':
                    kind = 'fork'
                elif marker == '+' and len(ports) == 4:
                    kind = 'cross'
                elif marker == '+' and len(ports) == 3:
                    raise ValueError('Ambiguous three-way plus; a true branch requires o')
                else:
                    kind = 'wire'
                if len(ports) < 2:
                    raise ValueError('Dangling visual wire')
                cell = {'kind': kind, 'ports': ports}
            # Validate all 55 pixels before accepting connectivity. Border sampling
            # alone accepts broken interior strokes and reversed receiving arrows.
            directions = {side: ('out' if side == 'bottom' else 'in') for side in ports}
            if cell['kind'] in ('input', 'output'):
                expected = glyphs._art(dict(cell, ports=directions, unindexed=True))
            elif cell['kind'] == 'operation':
                expected = [glyphs._border('top' in ports),
                            ' |'+glyphs._center(cell['binding'])+'| ',
                            ('>' if 'left' in ports else ' ')+'|'+glyphs._center(cell['label'])+'|'+('<' if 'right' in ports else ' '),
                            ' |_______| ', glyphs._pipe('bottom' in ports)]
                if 'bottom' not in ports:
                    raise ValueError('Operation requires its directed output connector')
            else:
                expected = glyphs._art(dict(cell, ports=directions, invisible=True))
            if art != tuple(expected):
                raise ValueError('Broken or directionally invalid complete glyph at '+str((row, column)))
            cells[(row, column)] = cell
    def adjacent(key, side):
        dr, dc = glyphs.DELTA[side]
        return key[0]+dr, key[1]+dc
    for key, cell in cells.items():
        for side in cell['ports']:
            neighbor = cells.get(adjacent(key, side))
            if not neighbor or glyphs.OPPOSITE[side] not in neighbor['ports']:
                raise ValueError('Disconnected visual connector at '+str((key, side)))
    def producers(key, entered, visited):
        state = key, entered
        if state in visited:
            return set()
        visited = visited | {state}
        cell = cells[key]
        if cell['kind'] in ('input', 'operation'):
            return {key} if entered == 'bottom' else set()
        if cell['kind'] == 'output':
            return set()
        exits = {glyphs.OPPOSITE[entered]} if cell['kind'] == 'cross' else cell['ports']-{entered}
        result = set()
        for side in exits:
            result.update(producers(adjacent(key, side), glyphs.OPPOSITE[side], visited))
        return result
    sources = {}
    for key, cell in cells.items():
        if cell['kind'] not in ('operation', 'output'):
            continue
        incoming = [side for side in glyphs.SIDES if side in cell['ports'] and side != 'bottom']
        if cell.get('binding', '').startswith('@'):
            binding = [int(number)-1 for number in cell['binding'][1:]]
            if sorted(binding) != list(range(len(incoming))):
                raise ValueError('Invalid visual operand binding')
            incoming = [incoming[index] for index in binding]
        origins = []
        for side in incoming:
            found = producers(adjacent(key, side), glyphs.OPPOSITE[side], set())
            if len(found) != 1:
                raise ValueError('Visual wire has missing or multiple producers')
            origins.append(found.pop())
        sources[key] = origins
    return {'cells': cells, 'sources': sources,
            'inputs': sorted(key for key, cell in cells.items() if cell['kind'] == 'input'),
            'outputs': sorted(key for key, cell in cells.items() if cell['kind'] == 'output')}


def evaluate(text, input_words, bits, cipher_columns):
    """Evaluate parsed glyphs; only the I/O word contract is supplied separately."""
    parsed = parse(text)
    if len(input_words) != len(parsed['inputs']):
        raise ValueError('Input word count disagrees with actual endpoints')
    mask = (1 << bits)-1
    memo = dict(zip(parsed['inputs'], input_words))
    pending = set()
    def value(key):
        if key in memo:
            return memo[key]
        if key in pending:
            raise ValueError('Visual computation has a cycle')
        pending.add(key)
        cell = parsed['cells'][key]
        args = [value(source) for source in parsed['sources'][key]]
        label = cell.get('label')
        if cell['kind'] == 'output':
            result = args[0]
        elif label.startswith('x'):
            if args:
                raise ValueError('Constant source has unexpected inputs')
            result = int(label[1:], 16)
        elif label in ('^', '&', '|'):
            if len(args) not in (2, 3):
                raise ValueError('Boolean glyph needs two or three actual inputs')
            from functools import reduce
            from operator import xor, and_, or_
            result = reduce({'^': xor, '&': and_, '|': or_}[label], args)
        elif label in ('+', '-', '*'):
            if len(args) != 2:
                raise ValueError('Binary glyph needs two actual inputs')
            a, b = args
            result = {'+': lambda: a+b, '-': lambda: a-b, '*': lambda: a*b}[label]()
        elif label == '!':
            if len(args) != 1:
                raise ValueError('Unary glyph needs one actual input')
            result = args[0] ^ mask
        elif label.startswith(('>>>', '<<<')):
            if len(args) != 1:
                raise ValueError('Rotation needs one actual input')
            amount = int(label[3:]) % bits
            result = ((args[0] >> amount) | (args[0] << (bits-amount))) if label.startswith('>>>') else ((args[0] << amount) | (args[0] >> (bits-amount)))
        elif label.startswith(('>>', '<<')):
            if len(args) != 1:
                raise ValueError('Shift needs one actual input')
            amount = int(label[2:])
            result = args[0] >> amount if label.startswith('>>') else args[0] << amount
        else:
            raise ValueError('Unsupported actual visual operation '+str(label))
        result &= mask
        memo[key] = result
        pending.remove(key)
        return result
    endpoints = {column: value(key) for key in parsed['outputs'] for column in [key[1]]}
    cipher = 0
    for column in cipher_columns:
        cipher = (cipher << bits) | endpoints[column]
    return {'cipher': cipher, 'display_words': [endpoints[key[1]] for key in parsed['outputs']],
            'node_values': memo, 'parsed': parsed}


def input_words(model, ir, values):
    words = []
    for binding in model['input_bindings']:
        value = 0
        source = values[binding['native_index']]
        width = ir['inputs'][binding['native_index']]['bits']
        for position in binding['positions']:
            value = (value << 1) | ((source >> (width-1-position)) & 1)
        words.append(value)
    return words
