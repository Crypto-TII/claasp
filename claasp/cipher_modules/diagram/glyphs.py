"""Native Python circuit glyphs: local definitions, visible dependencies.

The 5-by-11 cell grammar is shared with the web editor. Placement never uses
primitive names. This module has no external process or JavaScript dependency.
"""
import copy
import heapq
import json
import re
from collections import Counter

MARKER = '\n# CLAASP-TYPED-GLYPH 1\n'
SIDES = ('left', 'top', 'right', 'bottom')
DELTA = {'left': (0,-1), 'right': (0,1), 'top': (-1,0), 'bottom': (1,0)}
OPPOSITE = {'left':'right','right':'left','top':'bottom','bottom':'top'}


def _center(text):
    if len(text)>7: raise ValueError('Glyph label exceeds seven characters')
    left=(7-len(text))//2
    return ' '*left+text+' '*(7-len(text)-left)


def _pipe(active):
    return '     |     ' if active else ' '*11


def _border(active):
    return '  ___v___  ' if active else '  _______  '


def _input_art(cell):
    ports = cell['ports']
    label = '_______'
    if cell['kind'] == 'input' and not cell.get('unindexed'):
        label = _center('I'+str(cell['index']+1))
    marker = 'S' if cell.get('secret') else '|'
    return [_pipe('top' in ports), _border('top' in ports),
            ' '+marker+label+'| ', _pipe('bottom' in ports), _pipe('bottom' in ports)]


def _box_art(cell):
    ports = cell['ports']
    binding = _center('@21') if cell.get('reverse') else ' '*7
    left = '>' if ports.get('left') == 'in' else ' '
    right = '<' if ports.get('right') == 'in' else ' '
    return [_border('top' in ports), ' |'+binding+'| ',
            left+'('+_center(cell['tag'])+')'+right, ' |_______| ', _pipe('bottom' in ports)]


def _horizontal_span(middle, indices):
    for index in indices:
        middle[index] = '-'


def _branch_middle(cell, middle, horizontal_range):
    if 'left' in cell['ports']:
        _horizontal_span(middle, range(horizontal_range.start, 5))
    if 'right' in cell['ports']:
        _horizontal_span(middle, range(6, horizontal_range.stop))
    middle[5] = 'o' if cell['kind'] == 'fork' else '+'


def _route_shape(cell, middle, horizontal_range):
    ports = cell['ports']
    vertical = 'top' in ports or 'bottom' in ports
    horizontal = 'left' in ports or 'right' in ports
    if horizontal and not vertical:
        _horizontal_span(middle, horizontal_range)
    elif vertical and not horizontal:
        middle[5] = '|'
    else:
        _branch_middle(cell, middle, horizontal_range)
    return middle



def _invisible_art(cell):
    middle = _route_shape(cell, list(' '*11), range(0, 11))
    ports = cell['ports']
    return [_pipe('top' in ports), _pipe('top' in ports), ''.join(middle),
            _pipe('bottom' in ports), _pipe('bottom' in ports)]


def _arrow(side, direction):
    if direction == 'out':
        return '-'
    return '>' if side == 'left' else '<'


def _visible_wire_art(cell):
    ports = cell['ports']
    middle = _route_shape(cell, list(' |       | '), range(2, 9))
    for side, index in [('left', 0), ('right', 10)]:
        if side in ports:
            middle[index] = _arrow(side, ports[side])
    bottom = list(' |_______| ')
    if 'bottom' in ports:
        bottom[5] = '|'
    top_connection = '   |   ' if 'top' in ports else ' '*7
    return [_border('top' in ports), ' |'+top_connection+'| ',
            ''.join(middle), ''.join(bottom), _pipe('bottom' in ports)]


def _art(cell):
    renderers = {'input': _input_art, 'output': _input_art, 'tap': _input_art, 'box': _box_art}
    renderer = renderers.get(cell['kind'])
    if renderer is not None:
        return renderer(cell)
    if cell.get('invisible'):
        return _invisible_art(cell)
    return _visible_wire_art(cell)



class _GlyphGraph:
    """Lower ordered native operands into visible joins, selections and bundles."""

    def __init__(self, ir, port_selections, parallel):
        self.ir = ir
        self.port_selections = port_selections
        self.parallel = parallel
        self.calls = []
        self.values = {}
        self.source_offsets = {}
        self.inputs = []
        self.serial = 0
        self.joined = {}
        self.selections = {}
        self.targets = []
        self.cursor = 0

    def call(self, prefix, arguments, definition):
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        number, digits = self.serial, ''
        for _ in range(3):
            digits = alphabet[number % 36]+digits
            number //= 36
        if number:
            raise ValueError('Typed glyph alias capacity exceeded')
        self.serial += 1
        tag = prefix+digits
        index = len(self.calls)
        self.calls.append({'args': arguments, 'definition': dict(copy.deepcopy(definition), tag=tag),
                           'tag': tag, 'bits': definition['bits']})
        return ('call', index)

    def width(self, value):
        if value[0] == 'input':
            return self.ir['inputs'][value[1]]['bits']
        return self.calls[value[1]]['bits']

    def join(self, parts):
        if len(parts) == 1:
            return parts[0]
        middle = (len(parts)+1)//2
        left, right = self.join(parts[:middle]), self.join(parts[middle:])
        key = (left, right)
        if self.port_selections and key in self.joined:
            return self.joined[key]
        result = self.call('JN', [left, right], {'kind': 'join', 'bits': self.width(left)+self.width(right)})
        if self.port_selections:
            self.joined[key] = result
        return result

    def signature(self, node):
        if node['type'] in ('constant', 'intermediate_output', 'cipher_output'):
            return None
        if any(edge['source'] not in self.values for edge in node['operands']):
            return None
        sources = tuple(dict.fromkeys(self.values[edge['source']] for edge in node['operands']))
        return (node['type'], node['bits'], node['input_bits'], node['round'], json.dumps(node['description']), sources)

    def next_members(self):
        node = self.ir['nodes'][self.cursor]
        members = [(self.cursor, node)]
        key = self.signature(node) if self.parallel else None
        self.cursor += 1
        if key is not None:
            while self.cursor < len(self.ir['nodes']) and self.signature(self.ir['nodes'][self.cursor]) == key:
                members.append((self.cursor, self.ir['nodes'][self.cursor]))
                self.cursor += 1
        return members

    def selected_value(self, edge):
        value = self.values[edge['source']]
        positions = edge['positions']
        if positions == list(range(self.width(value))):
            return value
        key = (value, tuple(positions))
        if key not in self.selections:
            self.selections[key] = self.call('BS', [value], {'kind': 'selection', 'bits': len(positions), 'positions': positions})
        return self.selections[key]

    def port_positions(self, edge, arguments, offsets):
        value = self.values[edge['source']]
        if value not in offsets:
            offsets[value] = self.argument_width
            self.argument_width += self.width(value)
            arguments.append(value)
        offset = offsets[value]+self.source_offsets.get(edge['source'], 0)
        return [offset+position for position in edge['positions']]

    def member_definition(self, ordinal, node, arguments, offsets):
        local_positions = []
        for edge in node['operands']:
            if self.port_selections:
                local_positions.append(self.port_positions(edge, arguments, offsets))
            else:
                arguments.append(self.selected_value(edge))
        definition = {key: copy.deepcopy(value) for key, value in node.items() if key != 'operands'}
        definition['ordinal'] = ordinal
        if self.port_selections and local_positions:
            definition['operand_positions'] = local_positions
        return definition

    def emit_members(self, members):
        arguments, offsets = [], {}
        self.argument_width = 0
        definitions = [self.member_definition(ordinal, node, arguments, offsets) for ordinal, node in members]
        if len(arguments) > 2:
            middle = (len(arguments)+1)//2
            arguments = [self.join(arguments[:middle]), self.join(arguments[middle:])]
        node = members[-1][1]
        name = node['type']
        if name == 'word_operation':
            name = node['description'][0]
        prefix = re.sub('[^A-Za-z]', '', name)[:2].upper().ljust(2, 'N')
        if len(definitions) > 1:
            value = self.call('G'+prefix[0], arguments, {'kind': 'parallel',
                              'bits': sum(definition['bits'] for definition in definitions), 'members': definitions})
        else:
            value = self.call(prefix, arguments, dict(definitions[0], kind='native'))
        self.register_members(value, members)

    def register_members(self, value, members):
        offset = 0
        for _, node in members:
            self.values[node['id']] = value
            self.source_offsets[node['id']] = offset
            offset += node['bits']
            if node['type'] in ('intermediate_output', 'cipher_output'):
                self.targets.append(value)

    def build(self):
        for index, item in enumerate(self.ir['inputs']):
            value = ('input', index)
            self.inputs.append(value)
            self.values[item['id']] = value
        while self.cursor < len(self.ir['nodes']):
            self.emit_members(self.next_members())
        consumed = {value for call in self.calls for value in call['args']}
        for value in self.inputs+[('call', index) for index in range(len(self.calls))]:
            if value not in consumed and value not in self.targets:
                self.targets.append(value)
        return self.inputs, self.calls, self.targets


def _graph(ir, *, port_selections=False, parallel=False):
    return _GlyphGraph(ir, port_selections, parallel).build()



def _graph_limits(ir, strategy, max_cells, max_calls):
    strategies = ('semantic-legacy', 'direct-bus', 'semantic-ports', 'semantic-parallel', 'semantic-round')
    if strategy not in strategies:
        raise ValueError('Unknown native layout strategy')
    if type(max_cells) is not int or max_cells <= 0 or type(max_calls) is not int or max_calls <= 0:
        raise ValueError('Invalid native work bounds')
    if len(ir['nodes']) > max_calls:
        raise ValueError('Native component count exceeds max_calls')
    bits = sum(item['bits'] for item in ir['inputs'])
    bits += sum(node['bits']+sum(len(edge['positions']) for edge in node['operands']) for node in ir['nodes'])
    if bits > 2000000:
        raise ValueError('Native explicit bit expansion exceeds bound')


def _call_consumers(calls):
    consumers = {}
    for index, operation in enumerate(calls):
        for value in set(operation['args']):
            consumers.setdefault(value, []).append(index)
    return consumers


def _scheduling_rounds(ir, calls, consumers):
    ranks = {}
    for index in reversed(range(len(calls))):
        definition = calls[index]['definition']
        if definition['kind'] == 'native':
            rank = definition['round']
        elif definition['kind'] == 'parallel':
            rank = min(member['round'] for member in definition['members'])
        else:
            rank = min((ranks[consumer] for consumer in consumers.get(('call', index), [])), default=ir['rounds'])
        ranks[index] = rank
    return ranks


class _ReadyCalls:
    """Dependency-driven ready heaps with deterministic constant deferral."""

    def __init__(self, calls, consumers, available, pending, observers, priority):
        self.calls, self.consumers, self.pending = calls, consumers, pending
        self.observers, self.priority = observers, priority
        self.missing = [set(call['args'])-available for call in calls]
        self.ready, self.usable, self.eligible = [], [], set()
        for index, missing in enumerate(self.missing):
            if not missing:
                self._enqueue(index)

    def _constant_usable(self, index):
        value = ('call', index)
        return any(consumer in self.pending and self.missing[consumer] == {value}
                   for consumer in self.consumers.get(value, []))

    def _make_usable(self, index):
        if index not in self.eligible:
            heapq.heappush(self.usable, (self.priority(index), index))
            self.eligible.add(index)

    def _enqueue(self, index):
        heapq.heappush(self.ready, index)
        if self.calls[index]['args'] or ('call', index) in self.observers or self._constant_usable(index):
            self._make_usable(index)

    def _wake_last_constant(self, missing):
        if len(missing) != 1:
            return
        kind, index = next(iter(missing))
        if kind == 'call' and index in self.pending and not self.calls[index]['args']:
            self._make_usable(index)

    def publish(self, value):
        for consumer in self.consumers.get(value, []):
            if consumer not in self.pending:
                continue
            missing = self.missing[consumer]
            missing.discard(value)
            if not missing:
                self._enqueue(consumer)
            else:
                self._wake_last_constant(missing)

    def next(self):
        while self.usable:
            _, index = heapq.heappop(self.usable)
            if index in self.pending:
                return index
        while self.ready:
            index = heapq.heappop(self.ready)
            if index in self.pending:
                return index
        raise ValueError('No progress in native live-register scheduling')


class _RegisterScheduler:
    """Schedule ready calls and route liveness-preserving register lanes."""

    def __init__(self, ir, inputs, calls, targets, strategy, max_cells):
        self.ir, self.inputs, self.calls = ir, inputs, calls
        self.strategy, self.max_cells = strategy, max_cells
        self.consumers = _call_consumers(calls)
        self.scheduling_rounds = _scheduling_rounds(ir, calls, self.consumers)
        self.uses = Counter(value for call in calls for value in call['args'])
        self.uses.update(targets)
        self.slots = {value: index for index, value in enumerate(inputs)}
        self.active = set(self.slots.values())
        self.cells = {}
        self.row = 0
        self.maximum = len(inputs)-1
        self.pending = set(range(len(calls)))
        self.observers = set(targets)
        self.ready_calls = _ReadyCalls(calls, self.consumers, set(self.slots), self.pending,
                                      self.observers, self.priority)

    def place(self, col, kind, ports, **data):
        key = (self.row, col)
        if len(self.cells) >= self.max_cells:
            raise ValueError('Native routing exceeds max_cells')
        if key in self.cells:
            raise ValueError('Native routing collision')
        self.cells[key] = dict(kind=kind, ports=ports, **data)

    def fill(self, occupied):
        for col in sorted(self.active-occupied):
            self.place(col, 'wire', {'top': 'in', 'bottom': 'out'})

    def free(self, near=0):
        candidates = [col for col in range(self.maximum+2) if col not in self.active]
        if self.strategy == 'direct-bus':
            col = self.maximum+1
        else:
            col = min(candidates, key=lambda candidate: (abs(candidate-near), candidate))
        self.maximum = max(self.maximum, col)
        return col

    def horizontal(self, source, target, keep):
        side = 'right' if source < target else 'left'
        ports = {'top': 'in', side: 'out'}
        if keep:
            ports['bottom'] = 'out'
        self.place(source, 'fork' if keep else 'wire', ports)
        for col in range(min(source, target)+1, max(source, target)):
            ports = {'left': 'in', 'right': 'out'} if side == 'right' else {'right': 'in', 'left': 'out'}
            if col in self.active:
                ports.update(top='in', bottom='out')
            self.place(col, 'cross' if col in self.active else 'wire', ports)
        return 'left' if side == 'right' else 'right'

    def seed_inputs(self):
        for value in self.inputs:
            item = self.ir['inputs'][value[1]]
            self.place(self.slots[value], 'input', {'bottom': 'out'}, index=value[1], secret=item['role'] == 'key',
                       definition=dict(item, kind='input', index=value[1]))
        self.row += 1

    def next_call(self):
        return self.ready_calls.next()

    def priority(self, index):
        if self.strategy not in ('semantic-ports', 'semantic-parallel', 'semantic-round'):
            return (0, False, index)
        rank = self.scheduling_rounds[index] if self.strategy == 'semantic-round' else 0
        return (rank, self.calls[index]['definition']['kind'] != 'join', index)

    def copy_first(self, arguments, old):
        target = self.free(old[0])
        keep = self.uses[arguments[0]] > 1
        side = self.horizontal(old[0], target, keep)
        self.place(target, 'wire', {side: 'in', 'bottom': 'out'})
        self.fill(set(range(min(old[0], target), max(old[0], target)+1)))
        self.row += 1
        if not keep:
            self.active.discard(old[0])
        self.active.add(target)
        return target

    def target_lane(self, arguments, old):
        if not arguments:
            return self.free(), 0
        if self.strategy != 'direct-bus' and self.uses[arguments[0]] == 1:
            return old[0], 0
        reusable_second = len(arguments) == 2 and self.uses[arguments[1]] == 1 and arguments[0] != arguments[1]
        if self.strategy != 'direct-bus' and reusable_second:
            return old[1], 1
        return self.copy_first(arguments, old), 0

    def binary_box(self, call, arguments, old, target, replacement):
        source = old[1-replacement]
        value = arguments[1-replacement]
        side = self.horizontal(source, target, self.uses[value] > arguments.count(value))
        physical = [1-replacement, replacement] if side == 'left' else [replacement, 1-replacement]
        self.place(target, 'box', {'top': 'in', side: 'in', 'bottom': 'out'},
                   tag=call['tag'], definition=call['definition'], reverse=physical != [0, 1])
        self.fill(set(range(min(source, target), max(source, target)+1)))

    def emit_box(self, call, arguments, old, target, replacement):
        if len(arguments) == 2:
            self.binary_box(call, arguments, old, target, replacement)
        else:
            ports = {'top': 'in'} if arguments else {}
            self.place(target, 'box', dict(ports, bottom='out'), tag=call['tag'], definition=call['definition'])
            self.fill({target})
        self.row += 1

    def consume_operands(self, arguments):
        for value in arguments:
            self.uses[value] -= 1
            if not self.uses[value]:
                self.active.discard(self.slots.pop(value))

    def observe(self, value, target):
        self.uses[value] -= 1
        keep = self.uses[value] > 0
        ports = {'top': 'in'}
        if keep:
            ports['bottom'] = 'out'
        self.place(target, 'tap' if keep else 'output', ports)
        self.fill({target})
        self.row += 1
        if not keep:
            self.active.discard(target)
            self.slots.pop(value)

    def execute_call(self, index):
        call = self.calls[index]
        arguments = call['args']
        old = [self.slots[value] for value in arguments]
        target, replacement = self.target_lane(arguments, old)
        self.emit_box(call, arguments, old, target, replacement)
        self.pending.remove(index)
        self.consume_operands(arguments)
        value = ('call', index)
        self.slots[value] = target
        self.active.add(target)
        if value in self.observers:
            self.observe(value, target)
        self.ready_calls.publish(value)

    def capture_unused_inputs(self):
        for value in self.inputs:
            if value in self.observers and value in self.slots:
                target = self.slots.pop(value)
                self.place(target, 'output', {'top': 'in'})
                self.fill({target})
                self.row += 1
                self.active.discard(target)

    def build(self):
        self.seed_inputs()
        while self.pending:
            self.execute_call(self.next_call())
        self.capture_unused_inputs()
        if self.active:
            raise ValueError('Uncaptured native values remain live')
        cells = self.cells
        if self.strategy != 'direct-bus':
            cells = compact_tracks(cells, max_cells=self.max_cells)
        report = {'rows': max(row for row, col in cells)+1, 'cols': max(col for row, col in cells)+1,
                  'blocks': len(cells), 'pattern': 'live-register-program', 'strategy': self.strategy}
        return cells, report


def _build_grid(ir, *, strategy='semantic-legacy', max_cells=1000000, max_calls=20000):
    _graph_limits(ir, strategy, max_cells, max_calls)
    inputs, calls, targets = _graph(ir, port_selections=strategy in ('semantic-ports', 'semantic-parallel', 'semantic-round'),
                                   parallel=strategy in ('semantic-parallel', 'semantic-round'))
    if len(calls) > max_calls:
        raise ValueError('Native operation expansion exceeds max_calls')
    return _RegisterScheduler(ir, inputs, calls, targets, strategy, max_cells).build()



def build_grid(ir, *, strategy='semantic-auto', max_cells=1000000, max_calls=20000):
    if strategy!='semantic-auto':return _build_grid(ir,strategy=strategy,max_cells=max_cells,max_calls=max_calls)
    best = None
    errors = []
    for index, variant in enumerate(('semantic-legacy', 'semantic-ports', 'semantic-parallel', 'semantic-round')):
        try:
            cells, report = _build_grid(ir, strategy=variant, max_cells=max_cells, max_calls=max_calls)
            area = report['rows']*report['cols']
            candidate = ((area+report['blocks'], area, report['blocks']), index, cells, report)
            if best is None or candidate[:2] < best[:2]:
                best = candidate
            # Retain only the winner before constructing another full grid.
            del cells, report, candidate
        except ValueError as error:
            errors.append(str(error))
    if best is None:
        raise ValueError('; '.join(errors))
    _, _, cells, report = best
    report = dict(report, selectedVariant=report['strategy'], strategy='semantic-auto')
    return cells, report


def _rigid_rows(cells):
    rows = {}
    for (row, col), cell in sorted(cells.items()):
        if cell['kind'] == 'wire' and cell['ports'] == {'top': 'in', 'bottom': 'out'}:
            continue
        rows.setdefault(row, []).append((col, cell))
    return rows


def _horizontal_groups(items):
    groups = []
    for col, cell in items:
        previous = groups[-1][-1] if groups else None
        connected = previous and previous[0]+1 == col
        shared_ports = previous and ('right' in previous[1]['ports'] or 'left' in cell['ports'])
        if connected and shared_ports:
            groups[-1].append((col, cell))
        else:
            groups.append([(col, cell)])
    return groups


def _vertical_gap(output, col, cell, prior, target):
    if not prior:
        return
    if prior[1]['ports'].get('bottom') != 'out' or cell['ports'].get('top') != 'in':
        return
    for row in range(prior[0]+1, target):
        output[(row, col)] = {'kind': 'wire', 'ports': {'top': 'in', 'bottom': 'out'}}


def _compact_group(group, output, last, maximum):
    target = max((last.get(col, (-1, None))[0]+1 for col, cell in group), default=0)
    for col, cell in group:
        _vertical_gap(output, col, cell, last.get(col), target)
        output[(target, col)] = copy.deepcopy(cell)
        last[col] = (target, cell)
        if len(output) > maximum:
            raise ValueError('Compacted routing exceeds max_cells')


def compact_tracks(cells, *, max_cells=1000000):
    """Preserve rigid horizontal segments and per-column boundary order."""
    output, last = {}, {}
    for items in _rigid_rows(cells).values():
        for group in _horizontal_groups(items):
            _compact_group(group, output, last, max_cells)
    return output



def render_grid(cells,dimensions):
    records=[];lines=[]
    for r in range(dimensions['rows']):
        art=[_art(cells[(r,c)]) if (r,c) in cells else [' '*11]*5 for c in range(dimensions['cols'])]
        lines.extend(''.join(a[y] for a in art) for y in range(5))
    for (r,c),cell in sorted(cells.items()):
        if 'definition' in cell:records.append({'row':r,'col':c,'definition':copy.deepcopy(cell['definition'])})
    return '\n'.join(lines),records


def _encode_layout(ir, *, strategy='semantic-auto', max_cells=1000000,
           max_calls=20000, max_grid_area=2000000, max_text_bytes=64000000):
    if any(type(v) is not int or v<=0 for v in (max_grid_area,max_text_bytes)):
        raise ValueError('Invalid native output bounds')
    cells,dimensions=build_grid(ir,strategy=strategy,max_cells=max_cells,max_calls=max_calls)
    area=dimensions['rows']*dimensions['cols']
    if area>max_grid_area:raise ValueError('Native rectangular grid exceeds max_grid_area')
    records=[{'row':r,'col':c,'definition':copy.deepcopy(cell['definition'])}
             for (r,c),cell in sorted(cells.items()) if 'definition' in cell]
    primitive={k:copy.deepcopy(v) for k,v in ir.items() if k not in ('inputs','nodes')}
    footer=json.dumps({'primitive':primitive,'records':records},separators=(',',':'))
    # The full rectangle includes blank cells, not just occupied glyphs.
    estimated_bytes=area*55+dimensions['rows']*5-1+len(MARKER)+len(footer.encode('utf8'))+1
    if estimated_bytes>max_text_bytes:raise ValueError('Native glyph export exceeds max_text_bytes')
    text,_=render_grid(cells,dimensions)
    return text+MARKER+footer+'\n', cells, dimensions


def encode(ir, *, strategy='semantic-auto', max_cells=1000000,
           max_calls=20000, max_grid_area=2000000, max_text_bytes=64000000):
    text, _, _ = _encode_layout(ir, strategy=strategy, max_cells=max_cells,
                               max_calls=max_calls, max_grid_area=max_grid_area,
                               max_text_bytes=max_text_bytes)
    return text


def _wire_templates():
    result={}
    routes=[{'top':'in','bottom':'out'},{'left':'in','right':'out'},{'right':'in','left':'out'}]
    for side in ('left','right'):
        routes.extend([{'top':'in',side:'out'},{side:'in','bottom':'out'},{'top':'in',side:'out','bottom':'out'}])
    for side in ('left','right'):routes.append({'top':'in','bottom':'out',side:'in',OPPOSITE[side]:'out'})
    for ports in routes:
        kind={4:'cross',3:'fork'}.get(len(ports),'wire')
        for invisible in (False,True):
            cell={'kind':kind,'ports':ports,'invisible':invisible};result.setdefault(tuple(_art(cell)),[]).append(cell)
    return result


def decode(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    from claasp.cipher_modules.diagram.parser import decode as parse_visible_glyphs
    return parse_visible_glyphs(text, max_text_bytes=max_text_bytes, max_grid_area=max_grid_area)



_BOX_KINDS = ('input', 'box', 'output', 'tap')
_PORT_ANCHORS = {'left': 'west', 'right': 'east', 'top': 'north', 'bottom': 'south'}
_LABEL_ANCHORS = {'left': 'south east', 'right': 'south west', 'top': 'south east', 'bottom': 'north west'}


def _crop(options, key, size):
    value = options.get(key, [0, size])
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError('Invalid TikZ crop range')
    if any(type(item) is not int for item in value) or not 0 <= value[0] < value[1] <= size:
        raise ValueError('Invalid TikZ crop range')
    return value


def _wire_options(options, dimensions):
    xs, ys = options.get('columnSpacing', 3), options.get('rowSpacing', 1)
    if not isinstance(xs, (int, float)) or xs <= 0 or not isinstance(ys, (int, float)) or ys <= 0:
        raise ValueError('Invalid TikZ spacing')
    rows, columns, maximum = options.get('rowsPerPanel', 16), options.get('columnsPerPanel', 6), options.get('maxPanels', 256)
    if any(type(value) is not int or value <= 0 for value in (rows, columns, maximum)):
        raise ValueError('Invalid TikZ pagination')
    top, bottom = _crop(options, 'rowRange', dimensions['rows'])
    left, right = _crop(options, 'columnRange', dimensions['cols'])
    return {'xs': xs, 'ys': ys, 'rows': rows, 'columns': columns, 'maximum': maximum,
            'top': top, 'bottom': bottom, 'left': left, 'right': right}


def _panel_groups(cells, options):
    groups = {}
    for (row, col), cell in sorted(cells.items()):
        if options['top'] <= row < options['bottom'] and options['left'] <= col < options['right']:
            panel = ((row-options['top'])//options['rows'], (col-options['left'])//options['columns'])
            groups.setdefault(panel, []).append((row, col, cell))
    return groups


def _native_label(definition, registry):
    from claasp.cipher_modules.diagram.presentation import operation
    kind = definition.get('type')
    if kind in ('cipher_output', 'intermediate_output'):
        name = {'cipher_output': 'OUT', 'intermediate_output': 'OBSERVE'}[kind]
        return name+'/'+str(definition.get('bits', '?'))
    return operation(definition, registry, short=True)


def _cell_label(cell, key, registry):
    from claasp.cipher_modules.diagram.presentation import operation
    definition = cell.get('definition', {})
    kind = definition.get('kind')
    if cell['kind'] == 'input':
        name = 'key' if cell.get('secret') else 'input'
        label = name+'/'+str(definition.get('bits', '?'))
    elif kind == 'parallel':
        label = operation(definition['members'][0], registry, short=True)+' x'+str(len(definition['members']))
    elif kind == 'native':
        label = _native_label(definition, registry)
    elif kind in ('join', 'selection'):
        label = {'join': 'PACK', 'selection': 'SELECT'}[kind]+'/'+str(definition['bits'])
    else:
        label = cell['kind']
    if cell.get('reverse'):
        label += r'\\@21'
    if 'definition' in cell:
        label += r'\\'+key
    return label


def _box_node(row, col, cell, x, y, registry):
    from claasp.cipher_modules.diagram.presentation import escape
    label = _cell_label(cell, f'D{row}:{col}', registry)
    escaped = escape(label).replace(escape(chr(92)*2), chr(92)*2)
    return fr'\node[draw,align=center,minimum width=12mm,minimum height=4mm,font=\scriptsize] (N{row}x{col}) at ({x},{y}) {{{escaped}}};'


def _numbered_ports(row, col, cell):
    ordered = [side for side in SIDES if cell['ports'].get(side) == 'in']
    if cell.get('reverse'):
        ordered.reverse()
    return [fr'\node[font=\scriptsize,inner sep=2pt,anchor={_LABEL_ANCHORS[side]}] at (N{row}x{col}.{_PORT_ANCHORS[side]}) {{{number}}};'
            for number, side in enumerate(ordered, 1)]


def _inside_panel(row, col, top, left, options):
    return (top <= row < min(top+options['rows'], options['bottom'])
            and left <= col < min(left+options['columns'], options['right']))


def _segment(cells, row, col, cell, side, x, y, top, left, options):
    dr, dc = DELTA[side]
    nx, ny = x+dc*options['xs'], y-dr*options['ys']
    source = f'({x},{y})'
    if cell['kind'] in _BOX_KINDS:
        source = f'(N{row}x{col}.{_PORT_ANCHORS[side]})'
    neighbor = cells.get((row+dr, col+dc), {})
    target = f'({nx},{ny})'
    if _inside_panel(row+dr, col+dc, top, left, options) and neighbor.get('kind') in _BOX_KINDS:
        target = f'(N{row+dr}x{col+dc}.{_PORT_ANCHORS[OPPOSITE[side]]})'
    return fr'\draw[->] {source} -- {target};'


def _cell_segments(cells, row, col, cell, x, y, top, left, options):
    return [_segment(cells, row, col, cell, side, x, y, top, left, options)
            for side, direction in cell['ports'].items() if direction == 'out']


def _wire_panel(cells, panel, items, options, registry):
    top = options['top']+panel[0]*options['rows']
    left = options['left']+panel[1]*options['columns']
    lines, drawings = [r'\begin{tikzpicture}[>=stealth]'], []
    for row, col, cell in items:
        x, y = (col-left)*options['xs'], -(row-top)*options['ys']
        if cell['kind'] in _BOX_KINDS:
            lines.append(_box_node(row, col, cell, x, y, registry))
        if cell['kind'] == 'box':
            lines.extend(_numbered_ports(row, col, cell))
        drawings.extend(_cell_segments(cells, row, col, cell, x, y, top, left, options))
    lines.extend(drawings)
    lines.append(r'\end{tikzpicture}')
    return '\n'.join(lines)


def _present_grid(ir, cells, dimensions, options):
    from claasp.cipher_modules.diagram.presentation import parameter_registry, present
    view, legend = options.get('view', 'overview-detail'), options.get('legend', 'readable')
    if view not in ('overview', 'detail', 'overview-detail', 'wires') or legend not in ('readable', 'audit', 'none'):
        raise ValueError('Invalid TikZ presentation mode')
    wire_options = _wire_options(options, dimensions)
    panels = []
    if view == 'wires':
        registry = {key: value[0] for key, value in parameter_registry(ir).items()}
        groups = _panel_groups(cells, wire_options)
        if len(groups) > wire_options['maximum']:
            raise ValueError(f"TikZ needs {len(groups)} panels; crop or increase maxPanels")
        panels = [_wire_panel(cells, panel, items, wire_options, registry) for panel, items in sorted(groups.items())]
    return present(ir, cells, panels, options)


def tikz(ir, **options):
    cells, dimensions = build_grid(ir, strategy=options.get('strategy', 'semantic-auto'))
    return _present_grid(ir, cells, dimensions, options)
