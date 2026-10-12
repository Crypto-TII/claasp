"""Manual-vocabulary word blocks with edge-free, coordinate-local annotations.

The public human default uses this encoder. Plain bodies follow the existing
5x11 grammar; optional local annotations support fresh native reconstruction.
"""
import copy
import json
from collections import Counter, deque
from functools import reduce
from math import gcd

from . import glyphs, parser
from .validation import validate

MARKER = '\n# CLAASP-HUMAN-BLOCKS 1\n'
NODE_FIELDS = ('id', 'type', 'bits', 'input_bits', 'round', 'description')
FIELDS = {
    'input': {'kind', 'index', 'native_index', 'id', 'bits', 'role', 'positions', 'unused_positions'},
    'native': {'kind', 'ordinal', *NODE_FIELDS, 'operand_ports', 'operand_positions'},
    'native_boundary': {'kind', 'ordinal', *NODE_FIELDS, 'operand_ports', 'operand_positions', 'positions', 'flow'},
    'selection': {'kind', 'bits', 'positions', 'operand_ports', 'reference'},
    'join': {'kind', 'bits', 'operand_ports'},
}
SYMBOLS = {'XOR': '^', 'AND': '&', 'OR': '|', 'NOT': '!', 'REVERSE': 'REV',
           'MODADD': '+', 'MODSUB': '-', 'MODMUL': '*'}
WORDS = {'XOR': 'XOR', 'AND': 'AND', 'OR': 'OR', 'NOT': 'NOT', 'REVERSE': 'REV',
         'MODADD': 'MODA', 'MODSUB': 'MODS', 'MODMUL': 'MODM'}


def label(definition, style='symbols'):
    kind = definition['kind']
    if kind in ('selection', 'join'):
        return 'SEL'+definition.get('reference', '') if kind == 'selection' else 'JOIN'
    description = definition['description']
    if definition['type'] == 'constant':
        value = int(description[0], 0)
        text = 'x'+format(value, 'X')
    else:
        operation = description[0]
        if operation in ('ROTATE', 'SHIFT'):
            amount = description[1]
            if style == 'symbols':
                token = ('<<<' if amount < 0 else '>>>') if operation == 'ROTATE' else ('<<' if amount < 0 else '>>')
                text = token+str(abs(amount))
            else:
                # Manual word labels omit amounts, so retain numeric arrows.
                token = ('<<<' if amount < 0 else '>>>') if operation == 'ROTATE' else ('<<' if amount < 0 else '>>')
                text = token+str(abs(amount))
        else:
            text = (SYMBOLS if style == 'symbols' else WORDS).get(operation)
            if text is None:
                raise ValueError('Manual word projection does not yet support this operation; use audit')
            if operation in ('MODADD', 'MODSUB', 'MODMUL') and description[2] is not None:
                raise ValueError('Custom modulus needs a visible parameter reference; use audit until supported')
    capacity = 14 if definition['type'] == 'constant' else 7
    if len(text) > capacity:
        raise ValueError('Parameter exceeds visible manual label capacity; use audit until references are supported')
    return text


def art(cell, style='symbols'):
    if cell['kind'] == 'note':
        return ['  _______  ', ' |       | ', ' ('+glyphs._center(cell['text'])+') ', ' |_______| ', ' '*11]
    if cell['kind'] == 'swap':
        middle = '     <-----' if cell['partner'] > cell['column'] else '----->     '
        return ['     v     ', ' '*11, middle, ' '*11, '     |     ']
    if cell['kind'] == 'input' and not cell['definition']['positions']:
        text = 'SUNUSED' if cell.get('secret') else 'UNUSED'
        return ['  _______  ', ' |       | ', ' ('+glyphs._center(text)+') ', ' |_______| ', ' '*11]
    if cell['kind'] != 'box':
        return glyphs._art(cell)
    definition = cell['definition']
    text = label(definition, style)
    continued = definition.get('type') == 'constant' and len(text) > 7
    displayed = text[7:] if continued else text
    result = glyphs._box_art(dict(cell, tag=displayed, reverse=False))
    if continued:
        result[1] = ' |'+glyphs._center(text[:7])+'| '
    ports = cell['ports']
    # Existing manual helpers use the distinct free-text bracket vocabulary.
    left, right = ('[', ']') if definition['kind'] in ('selection', 'join') else ('|', '|')
    result[2] = ('>' if ports.get('left') == 'in' else ' ')+left+glyphs._center(displayed)+right+('<' if ports.get('right') == 'in' else ' ')
    # Generic native ordering is in local port metadata. Only noncommutative
    # operations require an explicit visible permutation (scheduler avoids it).
    if definition['kind'] == 'native' and definition['type'] == 'word_operation' and definition['description'][0] == 'MODSUB' and cell.get('reverse'):
        raise ValueError('Noncommutative manual binding requires an ordered physical placement')
    return result


class _WordGraph:
    def __init__(self, ir, bits):
        self.ir, self.bits = ir, bits
        self.calls, self.inputs, self.values = [], [], {}
        self.input_definitions, self.fake_inputs = [], []
        for native_index, item in enumerate(ir['inputs']):
            parts = []
            for start in range(0, item['bits'], bits):
                index = len(self.inputs)
                self.inputs.append(('input', index))
                self.fake_inputs.append(dict(item, bits=bits))
                self.input_definitions.append(dict(item, kind='input', index=index,
                    native_index=native_index, positions=list(range(start, start+bits))))
                parts.append(('input', index))
            self.values[item['id']] = parts
        for ordinal, node in enumerate(ir['nodes']):
            args = []
            for edge in node['operands']:
                positions = edge['positions']
                if len(positions) % bits:
                    raise ValueError('Partial word selection needs explicit word shape; use audit')
                for start in range(0, len(positions), bits):
                    args.append(self.select(edge['source'], positions[start:start+bits]))
            local = {key: copy.deepcopy(node[key]) for key in NODE_FIELDS}
            local['ordinal'] = ordinal
            local['operand_positions'] = []
            offset = 0
            for edge in node['operands']:
                local['operand_positions'].append(list(range(offset, offset+len(edge['positions']))))
                offset += len(edge['positions'])
            if node['type'] in ('cipher_output', 'intermediate_output'):
                parts = []
                for index, arg in enumerate(args):
                    definition = dict(local, kind='native_boundary', positions=list(range(index*bits, (index+1)*bits)))
                    parts.append(self.call([arg], definition))
                self.values[node['id']] = parts
            elif node['bits'] == bits and node['type'] in ('constant', 'word_operation') and len(args) <= 2:
                definition = dict(local, kind='native')
                label(definition)
                self.values[node['id']] = [self.call(args, definition)]
            else:
                raise ValueError('Manual projection needs uniform unary/binary words; use audit')

    def call(self, args, definition):
        index = len(self.calls)
        if definition['kind'] == 'selection':
            alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            number, digits = index, ''
            while True:
                digits = alphabet[number % 36]+digits
                number //= 36
                if not number:
                    break
            definition['reference'] = digits
        self.calls.append({'args': args, 'definition': definition, 'tag': 'local', 'bits': definition['bits']})
        return ('call', index)

    def select(self, identity, positions):
        word_indices = list(dict.fromkeys(position//self.bits for position in positions))
        parts = [self.values[identity][index] for index in word_indices]
        value = parts[0]
        for part in parts[1:]:
            width = self.width(value)+self.width(part)
            value = self.call([value, part], {'kind': 'join', 'bits': width})
        mask = [word_indices.index(position//self.bits)*self.bits+position%self.bits for position in positions]
        if mask == list(range(self.bits)) and len(parts) == 1:
            return value
        return self.call([value], {'kind': 'selection', 'bits': len(mask), 'positions': mask})

    def width(self, value):
        if value[0] == 'input':
            return self.bits
        definition = self.calls[value[1]]['definition']
        return len(definition['positions']) if definition['kind'] == 'native_boundary' else definition['bits']


class _Scheduler(glyphs._RegisterScheduler):
    def __init__(self, ir, graph, strategy, maximum, alignment='left'):
        used = Counter(value for call in graph.calls for value in call['args'])
        visible_inputs = []
        for native_index in range(len(ir['inputs'])):
            group = [value for value in graph.inputs if graph.input_definitions[value[1]]['native_index'] == native_index]
            live = [value for value in group if used[value]]
            if live:
                missing = [bit for value in group if value not in live for bit in graph.input_definitions[value[1]]['positions']]
                if missing:
                    graph.input_definitions[live[0][1]]['unused_positions'] = missing
                visible_inputs.extend(live)
            else:
                value = group[0]
                definition = graph.input_definitions[value[1]]
                definition['positions'] = []
                definition['unused_positions'] = list(range(definition['bits']))
                visible_inputs.append(value)
        graph.inputs = visible_inputs
        targets = [('call', index) for index, call in enumerate(graph.calls)
                   if not used[('call', index)] and call['definition']['kind'] != 'native_boundary']
        super().__init__(dict(ir, inputs=graph.fake_inputs), graph.inputs, graph.calls, targets, strategy, maximum)
        self.active = {self.slots[value] for value in self.inputs if used[value]}
        self.original_inputs = graph.input_definitions
        for index in reversed(range(len(self.calls))):
            definition = self.calls[index]['definition']
            self.scheduling_rounds[index] = definition.get('round', min((self.scheduling_rounds[consumer] for consumer in self.consumers.get(('call', index), [])), default=ir['rounds']-1))
        self.ready_calls = glyphs._ReadyCalls(self.calls, self.consumers, set(self.slots), self.pending, self.observers, self.priority)
        self.alignment = alignment
        self.critical = {}
        for index in reversed(range(len(self.calls))):
            self.critical[index] = 1+max((self.critical[consumer] for consumer in self.consumers.get(('call', index), [])), default=0)
        self.word_bits = graph.bits
        self.final_boundaries = {}

    def place(self, col, kind, ports, **data):
        definition = data.get('definition', {})
        stage = definition.get('round')
        executing = getattr(self, 'executing', None)
        if kind == 'input':
            stage = -1
        elif stage is None and executing is not None:
            stage = self.calls[executing]['definition'].get('round', self.scheduling_rounds[executing])
        super().place(col, kind, ports, stage=stage, **data)

    def build(self):
        self.seed_inputs()
        while self.pending:
            self.execute_call(self.next_call())
        self.capture_unused_inputs()
        if self.active:
            raise ValueError('Uncaptured manual values remain live')
        cells = self.cells if self.strategy == 'direct-bus' else _round_compact(self.cells, self.max_cells)
        cells = _final_row(cells)
        return cells, {'rows': max(row for row, col in cells)+1,
                       'cols': max(col for row, col in cells)+1,
                       'blocks': len(cells), 'pattern': 'word-register-program',
                       'strategy': self.strategy}

    def simple_output_exchange(self):
        finals = [(index, self.calls[index]) for index in self.pending
                  if self.calls[index]['definition'].get('type') == 'cipher_output']
        if len(finals) != 2 or self.final_boundaries:
            return
        finals.sort(key=lambda item: item[1]['definition']['positions'][0])
        values = [call['args'][0] for _, call in finals]
        if values[0] == values[1] or any(self.uses[value] != 1 for value in values):
            return
        targets = [call['definition']['positions'][0]//self.word_bits for _, call in finals]
        sources = [self.slots[value] for value in values]
        if targets != [0, 1] or sources != [1, 0] or self.active != {0, 1}:
            return
        self.place(0, 'swap', {'top': 'in', 'bottom': 'out', 'right': 'out'}, partner=1, column=0)
        self.place(1, 'swap', {'top': 'in', 'bottom': 'out', 'left': 'in'}, partner=0, column=1)
        self.row += 1
        self.slots.update(zip(values, targets))

    def priority(self, index):
        definition = self.calls[index]['definition']
        final = definition.get('type') == 'cipher_output'
        return (final, *super().priority(index))

    def routing_estimate(self, index):
        arguments = self.calls[index]['args']
        old = [self.slots[value] for value in arguments]
        expired = {self.slots[value] for value in arguments if self.uses[value] == arguments.count(value)}
        if not old:
            return 0, 0
        if expired:
            target = min(expired) if self.alignment == 'left' else max(expired)
        else:
            near = old[0] if self.alignment == 'left' else old[-1]
            free = [lane for lane in range(self.maximum+2) if lane not in self.active]
            target = min(free, key=lambda lane: (abs(lane-near), lane))
        crossings = sum(sum(min(source, target) < lane < max(source, target) for lane in self.active)
                        for source in old if source != target)
        return crossings, len(expired)

    def next_call(self):
        if self.strategy not in ('semantic-width', 'semantic-depth', 'semantic-crossings'):
            return super().next_call()
        eligible = [index for index in self.ready_calls.eligible if index in self.pending]
        if not eligible:
            return super().next_call()
        def cost(index):
            final = self.calls[index]['definition'].get('type') == 'cipher_output'
            crossings, expired = self.routing_estimate(index)
            if self.strategy == 'semantic-width':
                return final, -expired, crossings, index
            if self.strategy == 'semantic-depth':
                return final, -self.critical[index], crossings, index
            return final, crossings, -expired, index
        return min(eligible, key=cost)

    def seed_inputs(self):
        for value in self.inputs:
            definition = self.original_inputs[value[1]]
            ports = {'bottom': 'out'} if definition['positions'] else {}
            self.place(self.slots[value], 'input', ports, index=definition['index'],
                       secret=definition['role'] == 'key', definition=definition)
        self.row += 1

    def target_lane(self, arguments, old):
        # Native subtraction must have the same ordered physical ports as the
        # existing manual grammar. If neither old lane works, copy operand 2.
        index = getattr(self, 'executing', None)
        definition = self.calls[index]['definition'] if index is not None else {}
        is_sub = definition.get('type') == 'word_operation' and definition['description'][0] == 'MODSUB'
        if is_sub and len(arguments) == 2 and old[0] >= old[1]:
            target = self.maximum+1
            self.maximum = target
            keep = self.uses[arguments[1]] > 1
            side = self.horizontal(old[1], target, keep)
            self.place(target, 'wire', {side: 'in', 'bottom': 'out'})
            self.fill(set(range(old[1], target+1)))
            self.row += 1
            if not keep:
                self.active.discard(old[1])
            self.active.add(target)
            return target, 1
        if self.strategy != 'direct-bus' and arguments and (len(arguments) == 1 or arguments[0] != arguments[-1]):
            expired = [index for index, value in enumerate(arguments) if self.uses[value] == arguments.count(value)]
            if expired:
                replacement = min(expired, key=lambda index: old[index]) if self.alignment == 'left' else max(expired, key=lambda index: old[index])
                return old[replacement], replacement
            if self.alignment == 'right' and len(arguments) == 2:
                target = self.copy_first(list(reversed(arguments)), list(reversed(old)))
                return target, 1
        return super().target_lane(arguments, old)

    def relocate(self, value, target):
        source = self.slots[value]
        if source == target:
            return
        self.maximum = max(self.maximum, target)
        keep = source in self.final_boundaries
        side = self.horizontal(source, target, keep)
        self.place(target, 'wire', {side: 'in', 'bottom': 'out'})
        self.fill(set(range(min(source, target), max(source, target)+1)))
        self.row += 1
        if not keep:
            self.active.discard(source)
        self.active.add(target)
        self.slots[value] = target

    def final_boundary(self, index, call):
        self.simple_output_exchange()
        value = call['args'][0]
        target = call['definition']['positions'][0]//self.word_bits
        if target in self.active and self.slots[value] != target:
            occupant = next(token for token, lane in self.slots.items()
                            if lane == target and self.uses[token] > 0)
            temporary = next(lane for lane in range(self.maximum+2) if lane not in self.active)
            self.relocate(occupant, temporary)
        self.relocate(value, target)
        self.consume_operands(call['args'])
        self.active.add(target)
        self.final_boundaries[target] = call['definition']
        self.pending.remove(index)
        self.ready_calls.eligible.discard(index)
        self.ready_calls.publish(('call', index))
        if not any(self.calls[remaining]['definition'].get('type') == 'cipher_output' for remaining in self.pending):
            occupied = set(self.final_boundaries)
            for lane, definition in sorted(self.final_boundaries.items()):
                self.place(lane, 'output', {'top': 'in'}, definition=definition)
            self.fill(occupied)
            self.row += 1
            self.active.difference_update(occupied)
            self.final_boundaries.clear()

    def execute_call(self, index):
        self.executing = index
        call = self.calls[index]
        if call['definition']['kind'] != 'native_boundary':
            super().execute_call(index)
            self.ready_calls.eligible.discard(index)
            return
        if call['definition']['type'] == 'cipher_output':
            self.final_boundary(index, call)
            return
        args = call['args']
        old = [self.slots[value] for value in args]
        value = ('call', index)
        observational = self.uses[value] == 0
        call['definition']['flow'] = 'observe' if observational else 'alias'
        if observational:
            target = old[0]
            keep = self.uses[args[0]] > 1
        else:
            target, _ = self.target_lane(args, old)
            keep = True
        self.place(target, 'tap' if keep else 'output', dict({'top': 'in'}, **({'bottom': 'out'} if keep else {})),
                   definition=call['definition'])
        self.fill({target})
        self.row += 1
        self.pending.remove(index)
        self.ready_calls.eligible.discard(index)
        self.consume_operands(args)
        if keep and not observational:
            self.slots[value] = target
            self.active.add(target)
        elif not keep:
            self.active.discard(target)
        self.ready_calls.publish(value)


def _round_compact(cells, maximum):
    groups = []
    for row, items in glyphs._rigid_rows(cells).items():
        for order, group in enumerate(glyphs._horizontal_groups(items)):
            stages = [cell.get('stage') for _, cell in group if cell.get('stage') is not None]
            groups.append((max(stages, default=-1), row, order, group))
    output, last = {}, {}
    stage, floor = None, 0
    for current, _, _, group in sorted(groups, key=lambda item: item[:3]):
        if stage != current:
            floor = max((row for row, col in output), default=-1)+1
            stage = current
        target = max(floor, max((last.get(col, (-1, None))[0]+1 for col, _ in group), default=0))
        for col, cell in group:
            glyphs._vertical_gap(output, col, cell, last.get(col), target)
            output[(target, col)] = copy.deepcopy(cell)
            last[col] = target, cell
            if len(output) > maximum:
                raise ValueError('Round-preserving manual compaction exceeds max_cells')
    return output


def _final_row(cells):
    final = [(key, cell) for key, cell in cells.items()
             if cell.get('definition', {}).get('type') == 'cipher_output']
    if not final:
        return cells
    output = dict(cells)
    for key, _ in final:
        del output[key]
    bottom = max((row for row, col in output), default=-1)+1
    bottom = max(bottom, max(key[0] for key, _ in final))
    for (old, col), cell in final:
        for row in range(old, bottom):
            if (row, col) in output:
                raise ValueError('Final anchor would cross a later occupied lane')
            output[(row, col)] = {'kind': 'wire', 'ports': {'top': 'in', 'bottom': 'out'}}
        output[(bottom, col)] = cell
    return output


def _ranges(indices):
    indices = sorted(set(indices))
    groups = []
    for index in indices:
        if groups and index == groups[-1][-1]+1:
            groups[-1].append(index)
        else:
            groups.append([index])
    return [str(group[0]) if len(group) == 1 else f'{group[0]}-{group[-1]}' for group in groups]


def _decorate(cells, ir):
    output = dict(cells)
    legend = max(col for row, col in cells)+1
    inputs = [cell['definition'] for cell in cells.values() if cell.get('definition', {}).get('kind') == 'input']
    def put(row, text):
        if len(text) > 7:
            return  # Larger declarations stay explicit in local annotations.
        col = legend
        while (row, col) in output:
            col += 1
        output[(row, col)] = {'kind': 'note', 'ports': {}, 'text': text}
    row = 0
    for role, prefix in (('data', 'DATA'), ('key', 'KEY')):
        for span in _ranges(item['index']+1 for item in inputs if item['role'] == role and item['positions']):
            put(row, prefix+span)
            row += 1
    widths = [len(item['positions']) for item in inputs if item['positions']]
    widths.extend(len(cell['definition']['positions']) for cell in cells.values() if cell.get('definition', {}).get('kind') == 'native_boundary')
    bits = reduce(gcd, widths or [ir['output_bits']])
    declarations = {item['native_index']: item for item in inputs}
    offsets, total = {}, 0
    for index, item in sorted(declarations.items()):
        offsets[index], total = total, total+item['bits']//bits
    unused = [offsets[item['native_index']]+bit//bits+1 for item in inputs for bit in item.get('unused_positions', [])]
    if unused:
        put(row, 'UNUSED')
        row += 1
        for span in _ranges(unused):
            put(row, 'I'+span)
            row += 1
    if ir['rounds'] > 1:
        first = {}
        for (r, col), cell in sorted(cells.items()):
            definition = cell.get('definition', {})
            if 'round' in definition:
                first.setdefault(definition['round'], r)
        for stage, r in sorted(first.items()):
            put(r, 'R'+str(stage))
    observations = {(r, cell['definition']['round']) for (r, col), cell in cells.items()
                    if cell.get('definition', {}).get('type') == 'intermediate_output'}
    for r, stage in sorted(observations):
        put(r, 'OBS'+str(stage))
    return _final_row(output)


STRATEGIES = ('semantic-legacy', 'semantic-ports', 'semantic-round',
              'semantic-width', 'semantic-depth', 'semantic-crossings')


def _layout_score(metrics, preference):
    crossings, depth, width, cells = (metrics[key] for key in ('crossings', 'depth', 'width', 'cells'))
    area = depth*width
    if preference == 'crossings':
        return crossings, area, depth, width
    if preference == 'depth':
        return depth, crossings, width, cells
    if preference == 'width':
        return width, crossings, depth, cells
    return area+cells, crossings, depth, width


def build(ir, *, word_bits=None, strategy='semantic-auto', alignment='left',
          layout_preference='balanced', max_cells=1000000, max_calls=20000):
    """Compare generic schedules by measured crossings, depth and width."""
    validate(ir)
    if strategy not in ('semantic-auto', 'direct-bus', *STRATEGIES):
        raise ValueError('Unsupported manual block scheduling strategy')
    if alignment not in ('left', 'right') or layout_preference not in ('balanced', 'crossings', 'depth', 'width'):
        raise ValueError('Choose left/right alignment and balanced/crossings/depth/width layout preference')
    glyphs._graph_limits(ir, 'semantic-legacy', max_cells, max_calls)
    widths = [node['bits'] for node in ir['nodes'] if node['type'] == 'word_operation']
    bits = reduce(gcd, widths or [ir['output_bits']]) if word_bits is None else word_bits
    if type(bits) is not int or bits < 1 or any(item['bits'] % bits for item in ir['inputs']):
        raise ValueError('Supply uniform aligned positive word_bits')
    variants = STRATEGIES if strategy == 'semantic-auto' else (strategy,)
    best, reports, errors = None, [], []
    for index, variant in enumerate(variants):
        try:
            graph = _WordGraph(ir, bits)
            if len(graph.calls) > max_calls:
                raise ValueError('Manual word expansion exceeds max_calls')
            cells, report = _Scheduler(ir, graph, variant, max_cells, alignment).build()
            cells = _decorate(cells, ir)
            if len(cells) > max_cells:
                raise ValueError('Manual glyphs/legends exceed max_cells')
            report = dict(report, rows=max(row for row, col in cells)+1, cols=max(col for row, col in cells)+1, blocks=len(cells))
            metrics = {'crossings': sum(cell['kind'] == 'cross' for cell in cells.values()),
                       'depth': report['rows'], 'width': report['cols'], 'cells': report['blocks']}
            score = _layout_score(metrics, layout_preference)
            reports.append({'strategy': variant, 'metrics': metrics})
            candidate = score, index, cells, report, metrics
            if best is None or candidate[:2] < best[:2]:
                best = candidate
            del cells, report, candidate
        except ValueError as error:
            errors.append(str(error))
    if best is None:
        raise ValueError('; '.join(errors))
    _, _, cells, report, metrics = best
    return cells, dict(report, selected_variant=report['strategy'], strategy=strategy,
                       alignment=alignment, layout_preference=layout_preference,
                       metrics=metrics, candidates=reports)


def encode(ir, *, annotations=False, word_bits=None, operator_style='symbols',
           strategy='semantic-auto', alignment='left', layout_preference='balanced',
           wire_borders=False, max_cells=1000000, max_calls=20000,
           max_grid_area=2000000, max_text_bytes=64000000):
    if type(annotations) is not bool or type(wire_borders) is not bool or operator_style not in ('symbols', 'labels'):
        raise ValueError('Choose boolean annotations and symbols/labels')
    cells, report = build(ir, word_bits=word_bits, strategy=strategy, alignment=alignment,
                          layout_preference=layout_preference, max_cells=max_cells, max_calls=max_calls)
    if type(max_grid_area) is not int or max_grid_area < 1 or report['rows']*report['cols'] > max_grid_area:
        raise ValueError('Manual rectangular output exceeds max_grid_area')
    if type(max_text_bytes) is not int or max_text_bytes < 1:
        raise ValueError('max_text_bytes must be a positive integer')
    minimum_bytes = report['rows']*report['cols']*55+report['rows']*5-1
    if minimum_bytes > max_text_bytes:
        raise ValueError('Manual body exceeds max_text_bytes before rendering')
    lines, records = [], []
    for cell in cells.values():
        if cell['kind'] in ('wire', 'fork', 'cross'):
            cell['invisible'] = not wire_borders
    for row in range(report['rows']):
        rendered = [art(cells[(row, col)], operator_style) if (row, col) in cells else [' '*11]*5 for col in range(report['cols'])]
        lines.extend(''.join(cell[index] for cell in rendered) for index in range(5))
    for (row, col), cell in sorted(cells.items()):
        if 'definition' not in cell:
            continue
        definition = copy.deepcopy(cell['definition'])
        if cell['kind'] == 'box':
            physical = [side for side in glyphs.SIDES if cell['ports'].get(side) == 'in']
            definition['operand_ports'] = list(reversed(physical)) if cell.get('reverse') else physical
        elif definition['kind'] == 'native_boundary':
            definition['operand_ports'] = ['top']
        records.append({'row': row, 'col': col, 'definition': definition})
    body = '\n'.join(lines)
    primitive = {key: copy.deepcopy(ir[key]) for key in ('schema', 'name', 'cipher_type', 'output_bits', 'rounds')}
    text = body+MARKER+json.dumps({'format': 'claasp-human-blocks/1', 'primitive': primitive, 'records': records}, separators=(',', ':'))+'\n'
    if len(text.encode('utf-8')) > max_text_bytes:
        raise ValueError('Manual output/local verification exceeds max_text_bytes')
    if decode(text, max_grid_area=max_grid_area, max_text_bytes=max_text_bytes) != ir:
        raise ValueError('Fresh manual-block parsing changed native semantics')
    return text if annotations else body


def _metadata(text, max_text_bytes, max_grid_area):
    if len(text.encode('utf-8')) > max_text_bytes or text.count(MARKER) != 1:
        raise ValueError('Expected bounded manual body plus local annotations')
    body, footer = text.split(MARKER)
    manifest = json.loads(footer)
    if set(manifest) != {'format', 'primitive', 'records'} or manifest['format'] != 'claasp-human-blocks/1':
        raise ValueError('Invalid human-block framing')
    if set(manifest['primitive']) != {'schema', 'name', 'cipher_type', 'output_bits', 'rounds'}:
        raise ValueError('Original graph or unknown primitive fields are forbidden')
    lines = body.split('\n')
    width = max(map(len, lines), default=0)
    if len(lines) % 5 or width % 11 or not lines:
        raise ValueError('Human body must be an existing 5x11 manual block grid')
    rows, cols = len(lines)//5, width//11
    if rows*cols > max_grid_area or len(manifest['records']) > 20000:
        raise ValueError('Human block work bounds exceeded')
    records = {}
    expansion = 0
    for record in manifest['records']:
        if set(record) != {'row', 'col', 'definition'}:
            raise ValueError('Invalid local record')
        key = record['row'], record['col']
        definition = record['definition']
        if any(type(index) is not int or index < 0 for index in key) or key in records:
            raise ValueError('Invalid or duplicate local coordinate')
        if not isinstance(definition, dict) or set(definition)-FIELDS.get(definition.get('kind'), set()):
            raise ValueError('Hidden dependency or unsupported local annotation')
        if type(definition.get('bits')) is not int or not 0 < definition['bits'] <= 2000000:
            raise ValueError('Invalid local width')
        if definition['kind'] == 'native_boundary' and definition.get('flow', 'alias') not in ('alias', 'observe'):
            raise ValueError('Invalid observation flow role')
        if definition['kind'] == 'input' and (type(definition.get('index')) is not int or definition['index'] < 0):
            raise ValueError('Invalid visible input index')
        if definition['kind'] in ('native', 'native_boundary') and 'operand_positions' in definition:
            masks = definition['operand_positions']
            if not isinstance(masks, list) or any(not isinstance(mask, list) for mask in masks) or [bit for mask in masks for bit in mask] != list(range(definition['input_bits'])):
                raise ValueError('Nontrivial bit selections require an actual visible SEL helper')
        expansion += definition['bits']+definition.get('input_bits', 0)
        if expansion > 2000000:
            raise ValueError('Human explicit bit expansion exceeds work bounds')
        records[key] = definition
    return manifest, records, lines, rows, cols


def _manual_operation(definition, visible):
    ports = {'bottom': 'out'}
    for side, row, col, marker in [('top', 0, 5, 'v'), ('left', 2, 0, '>'), ('right', 2, 10, '<')]:
        if visible[row][col] == marker:
            ports[side] = 'in'
    ordered = definition.get('operand_ports')
    physical = [side for side in glyphs.SIDES if ports.get(side) == 'in']
    if not isinstance(ordered, list) or len(ordered) != len(physical) or set(ordered) != set(physical):
        raise ValueError('Local operand binding disagrees with visible ports')
    if definition.get('type') == 'word_operation' and definition['description'][0] == 'MODSUB' and ordered != physical:
        raise ValueError('Noncommutative binding must agree with its visible manual placement')
    cell = {'kind': 'box', 'ports': ports, 'definition': definition, 'tag': 'local'}
    if not any(tuple(art(cell, style)) == visible for style in ('symbols', 'labels')):
        raise ValueError('Native operation/parameter definition disagrees with visible glyph')
    return cell


def _swap_row(lines, row, cols):
    chunk = [line.ljust(cols*11) for line in lines[row*5:row*5+5]]
    positions = [col for col in range(cols) if chunk[0][col*11+5] == 'v']
    if len(positions) != 2 or chunk[1].strip() or chunk[3].strip():
        return None
    first, second = positions
    expected = [[' ']*(cols*11) for _ in range(5)]
    for col in positions:
        expected[0][col*11+5] = 'v'
        expected[4][col*11+5] = '|'
    expected[2][first*11+5] = '<'
    expected[2][second*11+5] = '>'
    for index in range(first*11+6, second*11+5):
        expected[2][index] = '-'
    if chunk != [''.join(line) for line in expected]:
        return None
    return {(row, col): {'kind': 'swap', 'ports': {'top': 'in', 'bottom': 'out'}, 'partner': other}
            for col, other in ((first, second), (second, first))}


def _note(visible):
    import re
    text = visible[2][2:9].strip()
    if not re.fullmatch(r'(?:DATA\d+(?:-\d+)?|KEY\d+(?:-\d+)?|UNUSED|I\d+(?:-\d+)?|R\d+|OBS\d+)', text):
        return None
    candidate = {'kind': 'note', 'ports': {}, 'text': text}
    return candidate if tuple(art(candidate)) == visible else None


def _read(records, lines, rows, cols):
    cells, choices = {}, {}
    templates = glyphs._wire_templates()
    for row in range(rows):
        swapped = _swap_row(lines, row, cols)
        if swapped:
            if any(key[0] == row for key in records):
                raise ValueError('A swap route cannot hide native annotations')
            cells.update(swapped)
            continue
        for col in range(cols):
            key = row, col
            visible = parser._cell_art(lines, row, col, cols)
            if all(not line.strip() for line in visible):
                continue
            definition = records.get(key)
            if definition and definition['kind'] == 'input':
                cell = parser._input_cell(definition, visible)
                if not definition['positions']:
                    cell['ports'] = {}
                if tuple(art(cell)) != visible:
                    raise ValueError('Input identity/secrecy disagrees with visible glyph')
            elif definition and definition['kind'] == 'native_boundary':
                cell = parser._sink_cell(visible, row, col)
                cell['definition'] = definition
                if definition.get('operand_ports') != ['top']:
                    raise ValueError('A native boundary needs its actual top input')
            elif definition:
                cell = _manual_operation(definition, visible)
            elif _note(visible):
                cell = _note(visible)
            elif visible in templates:
                choices[key] = copy.deepcopy(templates[visible])
                cell = choices[key][0]
            else:
                cell = parser._sink_cell(visible, row, col)
            cells[key] = cell
    if set(records)-set(cells):
        raise ValueError('Local annotation lacks a visible block')
    parser._resolved_alternatives(cells, choices)
    parser._connected_ports(cells)
    return cells


def _verify_notes(cells, records):
    import re
    inputs = [definition for definition in records.values() if definition['kind'] == 'input']
    roles = {role: {item['index']+1 for item in inputs if item['role'] == role and item['positions']}
             for role in ('data', 'key')}
    widths = [len(item['positions']) for item in inputs if item['positions']]
    widths.extend(len(definition['positions']) for definition in records.values() if definition['kind'] == 'native_boundary')
    bits = reduce(gcd, widths or [1])
    offset, offsets = 0, {}
    for index, item in sorted({item['native_index']: item for item in inputs}.items()):
        offsets[index], offset = offset, offset+item['bits']//bits
    unused = {offsets[item['native_index']]+bit//bits+1 for item in inputs for bit in item.get('unused_positions', [])}
    for (row, col), cell in cells.items():
        if cell['kind'] != 'note':
            continue
        text = cell['text']
        if text.startswith('OBS'):
            valid = any(key[0] == row and d.get('type') == 'intermediate_output' and d['round'] == int(text[3:]) for key, d in records.items())
        elif re.fullmatch(r'R\d+', text):
            valid = any(key[0] == row and d.get('round') == int(text[1:]) for key, d in records.items())
        elif text == 'UNUSED':
            valid = bool(unused)
        else:
            match = re.fullmatch(r'(DATA|KEY|I)(\d+)(?:-(\d+))?', text)
            start, stop = int(match[2]), int(match[3] or match[2])
            declared = set(range(start, stop+1))
            pool = unused if match[1] == 'I' else roles['data' if match[1] == 'DATA' else 'key']
            valid = start <= stop and declared <= pool
        if not valid:
            raise ValueError('Readable legend/stage cue disagrees with local native definitions')


def _input_declarations(records):
    declarations, covered, unused = {}, {}, {}
    for definition in records.values():
        if definition['kind'] != 'input':
            continue
        index = definition['native_index']
        if type(index) is not int or index < 0:
            raise ValueError('Invalid native declaration order')
        item = {key: definition[key] for key in ('id', 'bits', 'role')}
        if index in declarations and declarations[index] != item:
            raise ValueError('Repeated native declaration disagrees')
        declarations[index] = item
        selected = definition['positions']
        absent = definition.get('unused_positions', [])
        if not isinstance(selected, list) or not isinstance(absent, list) or any(type(bit) is not int or not 0 <= bit < item['bits'] for bit in selected+absent):
            raise ValueError('Input selection exceeds the declared width')
        covered.setdefault(index, set()).update(selected)
        unused.setdefault(index, set()).update(absent)
    if sorted(declarations) != list(range(len(declarations))):
        raise ValueError('Missing native input declaration')
    for index, item in declarations.items():
        if covered[index] & unused[index] or covered[index] | unused[index] != set(range(item['bits'])):
            raise ValueError('Input fragments must expose or explicitly declare every bit unused')
    return [declarations[index] for index in sorted(declarations)]


def _boundary_groups(records):
    groups = {}
    for key, definition in records.items():
        if definition['kind'] == 'native_boundary':
            groups.setdefault(definition['ordinal'], []).append((key, definition))
    for fragments in groups.values():
        first = fragments[0][1]
        shared = ('ordinal', *NODE_FIELDS, 'operand_positions')
        occupied = []
        for _, definition in fragments:
            if any(definition.get(field) != first.get(field) for field in shared):
                raise ValueError('Boundary fragments disagree about native metadata')
            occupied.extend(definition['positions'])
        if any(type(bit) is not int for bit in occupied) or sorted(occupied) != list(range(first['bits'])):
            raise ValueError('Boundary fragments must cover every bit exactly once')
        if first.get('type') == 'cipher_output':
            ordered = sorted(fragments, key=lambda item: item[0][1])
            if len({key[0] for key, _ in ordered}) != 1:
                raise ValueError('Final outputs must share a visible row')
            visible_order = [bit for _, definition in ordered for bit in definition['positions']]
            if visible_order != list(range(first['bits'])):
                raise ValueError('Final output positions disagree with visible left-to-right order')
    return groups


def _group_inputs(fragments):
    return [parser._adjacent(key, 'top') for key, _ in sorted(fragments, key=lambda item: min(item[1]['positions']))]


def _boundary_native(fragments, memo, native):
    definition = fragments[0][1]
    ordinal = definition['ordinal']
    if ordinal in native:
        return
    flat = [None]*definition['bits']
    for key, fragment in fragments:
        incoming = parser._flat_stream([memo[parser._adjacent(key, 'top')]])
        if len(incoming) != len(fragment['positions']):
            raise ValueError('Visible boundary width disagrees with its local fragment')
        for position, bit in zip(fragment['positions'], incoming):
            flat[position] = bit
    edges = []
    for source, bit in flat:
        if edges and edges[-1]['source'] == source:
            edges[-1]['positions'].append(bit)
        else:
            edges.append({'source': source, 'positions': [bit]})
    parser._native_node(definition, definition, [edges], flat, native)


def _trace(cells, groups):
    dependencies, followers = {}, {}
    for key, cell in cells.items():
        definition = cell.get('definition')
        for side, direction in cell['ports'].items():
            if direction != 'out':
                continue
            token = key, side
            if definition and definition['kind'] == 'native_boundary':
                incoming = _group_inputs(groups[definition['ordinal']])
            elif cell['kind'] == 'input':
                incoming = []
            elif cell['kind'] == 'swap':
                incoming = [parser._adjacent((key[0], cell['partner']), 'top')]
            elif cell['kind'] == 'box':
                incoming = [parser._adjacent(key, port) for port in definition['operand_ports']]
            else:
                incoming = [parser._adjacent(key, port) for port in parser._incoming_sides(cell, side)]
            dependencies[token] = incoming
            for predecessor in set(incoming):
                followers.setdefault(predecessor, []).append(token)
    remaining = {token: len(set(incoming)) for token, incoming in dependencies.items()}
    ready = deque(token for token, count in remaining.items() if not count)
    memo, native = {}, {}
    while ready:
        token = ready.popleft()
        cell = cells[token[0]]
        definition = cell.get('definition')
        arguments = [memo[predecessor] for predecessor in dependencies[token]]
        if cell['kind'] == 'input':
            stream = [{'source': definition['id'], 'positions': definition['positions']}]
        elif definition and definition['kind'] == 'native_boundary':
            _boundary_native(groups[definition['ordinal']], memo, native)
            if definition.get('flow') == 'observe':
                stream = memo[parser._adjacent(token[0], 'top')]
            elif definition.get('flow', 'alias') == 'alias':
                stream = [{'source': definition['id'], 'positions': definition['positions']}]
            else:
                raise ValueError('Invalid observation flow role')
        elif cell['kind'] == 'box':
            if definition['kind'] == 'native':
                stream = [parser._native_node(definition, definition, arguments, parser._flat_stream(arguments), native)]
            else:
                stream = parser._box_stream(definition, arguments, native)
        else:
            stream = arguments[0]
        memo[token] = stream
        for follower in followers.get(token, []):
            remaining[follower] -= 1
            if not remaining[follower]:
                ready.append(follower)
    if len(memo) != len(dependencies):
        raise ValueError('Unresolved or circular visible wires')
    for fragments in groups.values():
        _boundary_native(fragments, memo, native)
    return native


def _decode(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    """Freshly trace an annotated manual body; no expected/original IR is used."""
    manifest, records, lines, rows, cols = _metadata(text, max_text_bytes, max_grid_area)
    inputs = _input_declarations(records)
    groups = _boundary_groups(records)
    cells = _read(records, lines, rows, cols)
    _verify_notes(cells, records)
    native = _trace(cells, groups)
    if sorted(native) != list(range(len(native))):
        raise ValueError('Missing native execution ordinal')
    return validate(dict(manifest['primitive'], inputs=inputs, nodes=[native[index] for index in sorted(native)]))


def decode(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    """Recover native semantics from actual manual glyphs and local parameters."""
    if any(type(bound) is not int or bound < 1 for bound in (max_text_bytes, max_grid_area)):
        raise ValueError('Manual import bounds must be positive integers')
    try:
        return _decode(text, max_text_bytes=max_text_bytes, max_grid_area=max_grid_area)
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError('Malformed manual body or local native annotation') from error
