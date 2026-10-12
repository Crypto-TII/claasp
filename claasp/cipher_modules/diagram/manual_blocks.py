"""Manual-vocabulary word blocks with edge-free, coordinate-local annotations.

The public human default uses this encoder. Plain bodies follow the existing
5x11 grammar; optional local annotations support fresh native reconstruction.
"""
import copy
import heapq
import json
from collections import Counter, deque
from functools import reduce
from math import gcd

from . import glyphs, parser
from .validation import validate

MARKER = '\n# CLAASP-HUMAN-BLOCKS 1\n'
NODE_FIELDS = ('id', 'type', 'bits', 'input_bits', 'round', 'description')
FIELDS = {
    'discard': {'kind', 'bits'},
    'input': {'kind', 'index', 'native_index', 'id', 'bits', 'role', 'positions', 'unused_positions'},
    'native': {'kind', 'ordinal', *NODE_FIELDS, 'operand_ports', 'operand_positions'},
    'native_fragment': {'kind', 'ordinal', *NODE_FIELDS, 'operand_ports', 'operand_positions', 'positions'},
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
    if definition['type'] in ('sbox', 'linear_layer', 'mix_column'):
        return ({'sbox': 'S', 'linear_layer': 'L', 'mix_column': 'MC'} if style == 'symbols'
                else {'sbox': 'SBOX', 'linear_layer': 'LINL', 'mix_column': 'MIXC'})[definition['type']]
    if definition['type'] == 'constant':
        value = int(description[0], 0)
        text = 'x'+format(value, 'X')
    else:
        operation = description[0]
        if operation in ('ROTATE', 'SHIFT'):
            amount = description[1]
            # Both styles retain numeric arrows because bare words omit amounts.
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


def _base36(value):
    if type(value) is not int or value < 0:
        raise ValueError('Visible fragment references require nonnegative integer indexes')
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digits = ''
    while True:
        digits = alphabet[value % 36]+digits
        value //= 36
        if not value:
            return digits


def _fragment_reference(ordinal, word):
    tag = 'G'+_base36(ordinal)+'.W'+_base36(word)
    if len(tag) > 7:
        raise ValueError('Visible fragment group/word reference exceeds manual label capacity; use whole projection')
    return tag


def _fragment_identity(text):
    if not isinstance(text, str) or len(text) > 7 or not text.startswith('G'):
        raise ValueError('Invalid visible fragment group/word reference')
    pairs = [text[1:].split('.W')] if '.W' in text else [(text[1:split], text[split+1:]) for split in range(2, len(text)-1) if text[split] == 'W']
    candidates = []
    for pair in pairs:
        if len(pair) != 2 or any(not part or any(character not in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' for character in part) for part in pair):
            continue
        values = tuple(int(part, 36) for part in pair)
        if all(_base36(value) == part for value, part in zip(values, pair)):
            candidates.append(values)
    if len(candidates) != 1:
        raise ValueError('Invalid or ambiguous fragment reference; use G<group>.W<word>')
    return candidates[0]


def art(cell, style='symbols'):
    if cell['kind'] == 'note':
        return ['  _______  ', ' |       | ', ' ('+glyphs._center(cell['text'])+') ', ' |_______| ', ' '*11]
    if cell['kind'] == 'swap':
        middle = '     <-----' if cell['partner'] > cell['column'] else '----->     '
        return ['     v     ', ' '*11, middle, ' '*11, '     |     ']
    if cell['kind'] == 'input' and not cell['definition']['positions']:
        text = 'SUNUSED' if cell.get('secret') else 'UNUSED'
        return ['  _______  ', ' |       | ', ' ('+glyphs._center(text)+') ', ' |_______| ', ' '*11]
    if cell['kind'] in ('output', 'tap'):
        result = glyphs._art(cell)
        definition = cell.get('definition', {})
        text = 'OUT' if definition.get('type') == 'cipher_output' else 'OBS' if definition.get('type') == 'intermediate_output' else 'DEAD'
        result[2] = ' |'+glyphs._center(text)+'| '
        return result
    if cell['kind'] != 'box':
        return glyphs._art(cell)
    definition = cell['definition']
    text = label(definition, style)
    continued = definition.get('type') == 'constant' and len(text) > 7
    displayed = text[7:] if continued else text
    result = glyphs._box_art(dict(cell, tag=displayed, reverse=False))
    if continued:
        result[1] = ' |'+glyphs._center(text[:7])+'| '
    if definition['kind'] == 'native_fragment':
        positions = definition.get('positions')
        if not isinstance(positions, list) or not positions or any(type(bit) is not int or bit < 0 for bit in positions):
            raise ValueError('Invalid visible fragment word positions')
        word = positions[0]//len(positions)
        tag = _fragment_reference(definition['ordinal'], word)
        result[1] = ' |'+glyphs._center(tag)+'| '
        physical = [side for side in ('left', 'top', 'right', 'bottom') if cell['ports'].get(side) == 'in']
        binding = [physical.index(side)+1 for side in definition['operand_ports']]
        if binding != list(range(1, len(binding)+1)):
            displayed += '@'+''.join(map(str, binding))
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
    def __init__(self, ir, bits, gathering="linear", projection="whole"):
        self.ir, self.bits, self.gathering = ir, bits, gathering
        self.calls, self.inputs, self.values = [], [], {}
        self.raw_values, self.selection_cache, self.join_cache = {}, {}, {}
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
            args, pieces, filled = [], [], 0
            fragment = projection == 'wordwise' and node['type'] == 'word_operation' and node['description'][0] in ('XOR', 'AND', 'OR', 'NOT') and node['bits'] > bits and node['input_bits']//node['bits'] <= 3
            logical_bits = bits if fragment or node['type'] in ('cipher_output', 'intermediate_output') else node['bits']
            for edge in node['operands']:
                positions = edge['positions']
                if len(positions) % bits:
                    raise ValueError('Partial word selection needs explicit word shape; use audit')
                if node['type'] in ('sbox', 'linear_layer', 'mix_column'):
                    args.append(self.select(edge['source'], positions))
                    continue
                start = 0
                while start < len(positions):
                    count = min(logical_bits-filled, len(positions)-start)
                    pieces.append(self.select(edge['source'], positions[start:start+count]))
                    filled += count
                    start += count
                    if filled == logical_bits:
                        args.append(self.join(pieces))
                        pieces, filled = [], 0
            if pieces:
                raise ValueError('Logical word operands must cover complete native words; use audit')
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
            elif fragment:
                words, arity = node['bits']//bits, node['input_bits']//node['bits']
                parts = []
                for word in range(words):
                    definition = dict(local, kind='native_fragment', positions=list(range(word*bits, (word+1)*bits)))
                    operands = [args[operand*words+word] for operand in range(arity)]
                    parts.append(self.call(operands, definition))
                self.values[node['id']] = parts
            elif node['bits'] % bits == 0 and node['type'] in ('constant', 'word_operation', 'sbox', 'linear_layer', 'mix_column'):
                if node['type'] in ('sbox', 'linear_layer', 'mix_column'):
                    args = [self.join(args)]
                if len(args) > 2 and not (len(args) == 3 and node['type'] == 'word_operation' and node['description'][0] in ('XOR', 'AND', 'OR')):
                    raise ValueError('Manual operation exceeds its explicit physical port arity; use audit')
                definition = dict(local, kind='native')
                label(definition)
                value = self.call(args, definition)
                self.raw_values[node['id']] = value
            else:
                raise ValueError('Manual projection needs an admitted operation and aligned native width; use audit')

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
        self.calls.append({'args': args, 'definition': definition, 'tag': 'local', 'bits': len(definition['positions']) if definition['kind'] == 'native_fragment' else definition['bits']})
        return ('call', index)

    def join(self, parts):
        if not parts:
            raise ValueError('Native operation lacks its visible input')
        if self.gathering != 'balanced':
            value = parts[0]
            for part in parts[1:]:
                pair = value, part
                if self.gathering == 'shared-linear' and pair in self.join_cache:
                    value = self.join_cache[pair]
                else:
                    value = self.call(list(pair), {'kind': 'join', 'bits': self.width(value)+self.width(part)})
                    if self.gathering == 'shared-linear':
                        self.join_cache[pair] = value
            return value
        level = list(parts)
        while len(level) > 1:
            following = []
            for index in range(0, len(level), 2):
                if index+1 == len(level):
                    following.append(level[index])
                    continue
                pair = level[index], level[index+1]
                if pair not in self.join_cache:
                    self.join_cache[pair] = self.call(list(pair), {'kind': 'join', 'bits': sum(self.width(value) for value in pair)})
                following.append(self.join_cache[pair])
            level = following
        return level[0]

    def select(self, identity, positions):
        key = identity, tuple(positions)
        if key not in self.selection_cache:
            self.selection_cache[key] = self._select(identity, positions)
        return self.selection_cache[key]

    def _select(self, identity, positions):
        if identity in self.raw_values:
            value = self.raw_values[identity]
            if positions == list(range(self.width(value))):
                return value
            return self.call([value], {'kind': 'selection', 'bits': len(positions), 'positions': list(positions)})
        word_indices = list(dict.fromkeys(position//self.bits for position in positions))
        parts = [self.values[identity][index] for index in word_indices]
        value = self.join(parts)
        mask = [word_indices.index(position//self.bits)*self.bits+position%self.bits for position in positions]
        if mask == list(range(self.width(value))):
            return value
        return self.call([value], {'kind': 'selection', 'bits': len(mask), 'positions': mask})

    def width(self, value):
        if value[0] == 'input':
            return self.bits
        definition = self.calls[value[1]]['definition']
        return len(definition['positions']) if definition['kind'] in ('native_boundary', 'native_fragment') else definition['bits']


class _Scheduler(glyphs._RegisterScheduler):
    def __init__(self, ir, graph, strategy, maximum, alignment='left', lane_policy='compact'):
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
        self.lane_policy = lane_policy
        self.bank_ranges = {}
        for role in ('data', 'key'):
            lanes = [self.slots[value] for value in self.inputs if used[value] and self.original_inputs[value[1]]['role'] == role]
            if lanes and lanes == list(range(min(lanes), max(lanes)+1)):
                self.bank_ranges[role] = (min(lanes), max(lanes)+1)
        self.output_bank = 0
        self.bank_reason = 'ambiguous-compact-fallback'
        bank = self.bank_ranges.get('data')
        if bank and bank[1]-bank[0] == ir['output_bits']//graph.bits:
            self.output_bank, self.bank_reason = bank[0], 'explicit-data-role'
        self.value_roles = {value: self.original_inputs[value[1]]['role'] for value in self.inputs}
        for index, call in enumerate(self.calls):
            roles = {self.value_roles.get(value, 'unspecified') for value in call['args']}
            role = 'data' if 'data' in roles else 'key' if roles == {'key'} else 'unspecified'
            self.value_roles[('call', index)] = role
        for index in reversed(range(len(self.calls))):
            definition = self.calls[index]['definition']
            self.scheduling_rounds[index] = definition.get('round', min((self.scheduling_rounds[consumer] for consumer in self.consumers.get(('call', index), [])), default=ir['rounds']-1))
        self.ready_calls = glyphs._ReadyCalls(self.calls, self.consumers, set(self.slots), self.pending, self.observers, self.priority)
        self.alignment = alignment
        self.critical = {}
        for index in reversed(range(len(self.calls))):
            self.critical[index] = 1+max((self.critical[consumer] for consumer in self.consumers.get(('call', index), [])), default=0)
        native_layers = {item['id']: 0 for item in ir['inputs']}
        ordinal_layers = {}
        for ordinal, node in enumerate(ir['nodes']):
            layer = 1+max((native_layers[edge['source']] for edge in node['operands']), default=0)
            native_layers[node['id']] = layer
            ordinal_layers[ordinal] = layer
        self.layers = {}
        for index, call in enumerate(self.calls):
            prior = max((self.layers[value[1]] if value[0] == 'call' else 0 for value in call['args']), default=0)
            self.layers[index] = ordinal_layers[call['definition']['ordinal']] if call['definition']['kind'] in ('native', 'native_boundary', 'native_fragment') else prior
        self.word_bits = graph.bits
        self.final_boundaries = {}
        self.constant_stages = [(call['definition']['round'], index) for index, call in enumerate(self.calls)
                                if call['definition'].get('type') == 'constant']
        heapq.heapify(self.constant_stages)

    def place(self, col, kind, ports, **data):
        definition = data.get('definition', {})
        stage = definition.get('round')
        executing = getattr(self, 'executing', None)
        if kind == 'input':
            stage = -1
        elif stage is None and executing is not None:
            stage = self.calls[executing]['definition'].get('round', self.scheduling_rounds[executing])
        if kind in ('output', 'tap') and not definition:
            if executing is None:
                raise ValueError('Discard sink lacks its computed width')
            data['definition'] = {'kind': 'discard', 'bits': self.calls[executing]['bits']}
        call_kind = self.calls[executing]['definition']['kind'] if executing is not None else 'input'
        layer = 2*self.layers.get(executing, 0)+int(call_kind in ('selection', 'join'))
        super().place(col, kind, ports, stage=stage, layer=layer, **data)

    def build(self):
        self.seed_inputs()
        while self.pending:
            self.execute_call(self.next_call())
        self.capture_unused_inputs()
        if self.active:
            raise ValueError('Uncaptured manual values remain live')
        cells = self.cells if self.strategy == 'direct-bus' else _round_compact(self.cells, self.max_cells, align_layers=self.strategy == 'semantic-layer')
        cells = _final_row(cells)
        return cells, {'rows': max(row for row, col in cells)+1,
                       'cols': max(col for row, col in cells)+1,
                       'blocks': len(cells), 'pattern': 'word-register-program',
                       'strategy': self.strategy, 'lane_policy': self.lane_policy,
                       'banks': {role: list(bounds) for role, bounds in self.bank_ranges.items()},
                       'output_bank': self.output_bank if self.lane_policy == 'state' else 0,
                       'bank_reason': self.bank_reason if self.lane_policy == 'state' else 'compact-policy'}

    def simple_output_exchange(self):
        finals = [(index, self.calls[index]) for index in self.pending
                  if self.calls[index]['definition'].get('type') == 'cipher_output']
        if len(finals) != 2 or self.final_boundaries:
            return
        finals.sort(key=lambda item: item[1]['definition']['positions'][0])
        values = [call['args'][0] for _, call in finals]
        if values[0] == values[1] or any(self.uses[value] != 1 for value in values):
            return
        targets = [call['definition']['positions'][0]//self.word_bits+(self.output_bank if self.lane_policy == 'state' else 0) for _, call in finals]
        sources = [self.slots[value] for value in values]
        if targets[1] != targets[0]+1 or sources != list(reversed(targets)) or self.active != set(targets):
            return
        self.place(targets[0], 'swap', {'top': 'in', 'bottom': 'out', 'right': 'out'}, partner=targets[1], column=targets[0])
        self.place(targets[1], 'swap', {'top': 'in', 'bottom': 'out', 'left': 'in'}, partner=targets[0], column=targets[1])
        self.row += 1
        self.slots.update(zip(values, targets))

    def priority(self, index):
        definition = self.calls[index]['definition']
        final = definition.get('type') == 'cipher_output'
        return (self.scheduling_rounds[index], final, *super().priority(index))

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
        chosen = self._next_scheduled_call()
        while self.constant_stages and self.constant_stages[0][1] not in self.pending:
            heapq.heappop(self.constant_stages)
        if self.constant_stages and self.constant_stages[0][0] < self.scheduling_rounds[chosen]:
            # A deferred constant cannot be born on a reused lane in a later
            # round and then be hoisted across that lane's existing lifetime.
            if chosen in self.ready_calls.eligible:
                heapq.heappush(self.ready_calls.usable, (self.priority(chosen), chosen))
            else:
                heapq.heappush(self.ready_calls.ready, chosen)
            return heapq.heappop(self.constant_stages)[1]
        return chosen

    def _next_scheduled_call(self):
        if self.strategy == 'semantic-layer':
            eligible = [index for index in self.ready_calls.eligible if index in self.pending]
            eligible.extend(index for index in self.pending if not self.calls[index]['args'] and index not in eligible)
            if eligible:
                return min(eligible, key=lambda index: (self.scheduling_rounds[index], 2*self.layers[index]+int(self.calls[index]['definition']['kind'] in ('selection', 'join')), index))
        if self.strategy not in ('semantic-width', 'semantic-depth', 'semantic-crossings'):
            return super().next_call()
        eligible = [index for index in self.ready_calls.eligible if index in self.pending]
        if not eligible:
            return super().next_call()
        def cost(index):
            final = self.calls[index]['definition'].get('type') == 'cipher_output'
            crossings, expired = self.routing_estimate(index)
            if self.strategy == 'semantic-width':
                return self.scheduling_rounds[index], final, -expired, crossings, index
            if self.strategy == 'semantic-depth':
                return self.scheduling_rounds[index], final, -self.critical[index], crossings, index
            return self.scheduling_rounds[index], final, crossings, -expired, index
        return min(eligible, key=cost)

    def seed_inputs(self):
        for value in self.inputs:
            definition = self.original_inputs[value[1]]
            ports = {'bottom': 'out'} if definition['positions'] else {}
            self.place(self.slots[value], 'input', ports, index=definition['index'],
                       secret=definition['role'] == 'key', definition=definition)
        self.row += 1

    def free(self, near=0):
        index = getattr(self, 'executing', None)
        role = self.value_roles.get(('call', index)) if index is not None else None
        bank = self.bank_ranges.get(role) if getattr(self, 'lane_policy', 'compact') == 'state' else None
        if not bank:
            return super().free(near)
        candidates = [lane for lane in range(*bank) if lane not in self.active]
        if not candidates:
            start = max(end for _, end in self.bank_ranges.values())
            candidates = [lane for lane in range(start, self.maximum+2) if lane not in self.active]
            if not candidates:
                candidates = [max(start, self.maximum+1)]
        lane = min(candidates, key=lambda candidate: (abs(candidate-near), candidate))
        self.maximum = max(self.maximum, lane)
        return lane

    def target_lane(self, arguments, old):
        if len(arguments) == 3:
            starts = [lane for lane in range(self.maximum+2)
                      if not self.active.intersection(range(lane, lane+3))]
            near = sorted(old)[1]
            start = min(starts, key=lambda lane: (abs(lane+1-near), lane)) if starts else self.maximum+1
            return start+1, 1
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
        if self.lane_policy == 'state' and not is_sub and len(arguments) == 2:
            data = [position for position, value in enumerate(arguments) if self.value_roles.get(value) == 'data']
            if len(data) == 1 and self.uses[arguments[data[0]]] == arguments.count(arguments[data[0]]):
                return old[data[0]], data[0]
        if self.strategy != 'direct-bus' and arguments and (len(arguments) == 1 or arguments[0] != arguments[-1]):
            expired = [index for index, value in enumerate(arguments) if self.uses[value] == arguments.count(value)]
            if expired:
                replacement = min(expired, key=lambda index: old[index]) if self.alignment == 'left' else max(expired, key=lambda index: old[index])
                return old[replacement], replacement
            if self.alignment == 'right' and len(arguments) == 2:
                target = self.copy_first(list(reversed(arguments)), list(reversed(old)))
                return target, 1
        return super().target_lane(arguments, old)

    def emit_box(self, call, arguments, old, target, replacement):
        if len(arguments) != 3:
            return super().emit_box(call, arguments, old, target, replacement)
        # Three physical lanes keep every operand explicit, including repeats.
        # Copy each live source before consuming any original operand.
        lanes = [target-1, target, target+1]
        self.maximum = max(self.maximum, lanes[-1])
        copied = Counter()
        for value, source, lane in zip(arguments, old, lanes):
            copied[value] += 1
            keep = self.uses[value] > copied[value]
            side = self.horizontal(source, lane, keep)
            self.place(lane, 'wire', {side: 'in', 'bottom': 'out'})
            self.fill(set(range(min(source, lane), max(source, lane)+1)))
            if not keep:
                self.active.discard(source)
            self.active.add(lane)
            self.row += 1
        self.horizontal(lanes[0], target, False)
        self.horizontal(lanes[2], target, False)
        self.place(target, 'box', {'left': 'in', 'top': 'in', 'right': 'in', 'bottom': 'out'},
                   definition=call['definition'], tag=call['tag'], reverse=False)
        self.fill(set(lanes))
        self.active.difference_update((lanes[0], lanes[2]))
        self.row += 1

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
        target = call['definition']['positions'][0]//self.word_bits+(self.output_bank if self.lane_policy == 'state' else 0)
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


def _round_compact(cells, maximum, align_layers=False):
    groups = []
    for row, items in glyphs._rigid_rows(cells).items():
        for order, group in enumerate(glyphs._horizontal_groups(items)):
            stages = [cell.get('stage') for _, cell in group if cell.get('stage') is not None]
            layer = max((cell.get('layer', 0) for _, cell in group), default=0) if align_layers else 0
            groups.append((max(stages, default=-1), layer, row, order, group))
    output, last = {}, {}
    stage, floor = None, 0
    for current, layer, _, _, group in sorted(groups, key=lambda item: item[:4]):
        if stage != (current, layer):
            floor = max((row for row, col in output), default=-1)+1
            stage = current, layer
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
    def put(row, text, vector_label=None):
        if len(text) > 7:
            return  # Larger declarations stay explicit in local annotations.
        col = legend
        while (row, col) in output:
            col += 1
        output[(row, col)] = {'kind': 'note', 'ports': {}, 'text': text}
        if vector_label is not None:
            output[(row, col)]['vector_label'] = vector_label
    row = 0
    for role, prefix in (('data', 'DATA'), ('key', 'KEY')):
        for span in _ranges(item['index']+1 for item in inputs if item['role'] == role and item['positions']):
            from .presentation import selections
            ends = [int(part) for part in span.split('-')]
            words = set(range(ends[0], ends[-1]+1))
            by_input = {}
            for item in inputs:
                if item['index']+1 in words:
                    by_input.setdefault(item['native_index'], set()).update(item['positions'])
            visible = prefix+' '+', '.join('I'+str(index)+' bits '+selections(sorted(positions)) for index, positions in sorted(by_input.items()))
            put(row, prefix+span, visible)
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
            from .presentation import selections
            ends = [int(part) for part in span.split('-')]
            words = set(range(ends[0], ends[-1]+1))
            by_input = {}
            for item in inputs:
                for bit in item.get('unused_positions', []):
                    if offsets[item['native_index']]+bit//bits+1 in words:
                        by_input.setdefault(item['native_index'], set()).add(bit)
            visible = ', '.join('I'+str(index)+' bits '+selections(sorted(positions)) for index, positions in sorted(by_input.items()))
            put(row, 'I'+span, visible)
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


def infer_word_bits(ir):
    """Conservative common granularity; it does not infer a two-dimensional shape."""
    widths = [node['bits'] for node in ir['nodes']]
    widths.extend(len(edge['positions']) for node in ir['nodes'] for edge in node['operands'])
    return reduce(gcd, widths or [ir['output_bits']])


def build(ir, *, word_bits=None, strategy='semantic-auto', alignment='left', gathering='linear', lane_policy='compact', projection='whole',
          layout_preference='balanced', max_cells=1000000, max_calls=20000):
    """Compare generic schedules by measured crossings, depth and width."""
    validate(ir)
    if projection not in ('whole', 'wordwise'):
        raise ValueError('Choose whole or wordwise projection')
    if lane_policy not in ('compact', 'state'):
        raise ValueError('Choose compact or state lane_policy')
    if gathering not in ('linear', 'shared-linear', 'balanced'):
        raise ValueError('Choose linear, shared-linear or balanced gathering')
    if strategy not in ('semantic-auto', 'direct-bus', 'semantic-layer', *STRATEGIES):
        raise ValueError('Unsupported manual block scheduling strategy')
    if alignment not in ('left', 'right') or layout_preference not in ('balanced', 'crossings', 'depth', 'width'):
        raise ValueError('Choose left/right alignment and balanced/crossings/depth/width layout preference')
    glyphs._graph_limits(ir, 'semantic-legacy', max_cells, max_calls)
    bits = infer_word_bits(ir) if word_bits is None else word_bits
    if type(bits) is not int or bits < 1 or any(item['bits'] % bits for item in ir['inputs']):
        raise ValueError('Supply uniform aligned positive word_bits')
    variants = STRATEGIES if strategy == 'semantic-auto' else (strategy,)
    best, reports, errors, rejected = None, [], [], []
    for index, variant in enumerate(variants):
        try:
            graph = _WordGraph(ir, bits, gathering, projection)
            if len(graph.calls) > max_calls:
                raise ValueError('Manual word expansion exceeds max_calls')
            cells, report = _Scheduler(ir, graph, variant, max_cells, alignment, lane_policy).build()
            cells = _decorate(cells, ir)
            # Reject structurally disconnected schedules before comparing costs.
            # The winner is still reparsed from its actual exported text.
            parser._connected_ports(cells)
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
            rejected.append({'strategy': variant, 'reason': str(error)})
    if best is None:
        raise ValueError('; '.join(errors))
    _, _, cells, report, metrics = best
    return cells, dict(report, selected_variant=report['strategy'], strategy=strategy,
                       alignment=alignment, layout_preference=layout_preference, gathering=gathering, projection=projection,
                       metrics=metrics, candidates=reports, rejected_candidates=rejected)


def _encode_layout(ir, *, annotations=True, word_bits=None, operator_style='symbols',
           strategy='semantic-auto', alignment='left', layout_preference='balanced', gathering='linear', lane_policy='compact', projection='whole',
           wire_borders=False, max_cells=1000000, max_calls=20000,
           max_grid_area=2000000, max_text_bytes=64000000):
    if type(annotations) is not bool or type(wire_borders) is not bool or operator_style not in ('symbols', 'labels'):
        raise ValueError('Choose boolean annotations and symbols/labels')
    cells, report = build(ir, word_bits=word_bits, strategy=strategy, alignment=alignment,
                          layout_preference=layout_preference, gathering=gathering, lane_policy=lane_policy, projection=projection, max_cells=max_cells, max_calls=max_calls)
    if type(max_grid_area) is not int or max_grid_area < 1 or report['rows']*report['cols'] > max_grid_area:
        raise ValueError('Manual rectangular output exceeds max_grid_area')
    if type(max_text_bytes) is not int or max_text_bytes < 1:
        raise ValueError('max_text_bytes must be a positive integer')
    minimum_bytes = report['rows']*report['cols']*55+report['rows']*5-1
    if minimum_bytes > max_text_bytes:
        raise ValueError('Manual body exceeds max_text_bytes before rendering')
    lines, records = [], []
    for cell in cells.values():
        if cell['kind'] == 'box':
            physical = [side for side in glyphs.SIDES if cell['ports'].get(side) == 'in']
            cell['definition']['operand_ports'] = list(reversed(physical)) if cell.get('reverse') else physical
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
    return text, cells, report


def encode(ir, *, annotations=False, **options):
    text, _, _ = _encode_layout(ir, annotations=annotations, **options)
    return text if annotations else text.split(MARKER)[0]


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
        if definition['kind'] in ('native', 'native_boundary', 'native_fragment') and 'operand_positions' in definition:
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
    comparison = visible
    if definition['kind'] == 'native_fragment':
        expected = art(cell)
        identity = _fragment_identity(visible[1][2:9].strip())
        if identity != (definition['ordinal'], definition['positions'][0]//len(definition['positions'])):
            raise ValueError('Native fragment identity disagrees with visible group/word reference')
        comparison = tuple(expected[1] if index == 1 else line for index, line in enumerate(visible))
    if not any(tuple(art(cell, style)) == comparison for style in ('symbols', 'labels')):
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
            elif definition and definition['kind'] in ('native_boundary', 'discard'):
                candidates = [{'kind': kind, 'ports': dict(top='in', **({'bottom': 'out'} if kind == 'tap' else {})), 'definition': definition} for kind in ('output', 'tap')]
                cell = next((candidate for candidate in candidates if tuple(art(candidate)) == visible), None)
                if cell is None:
                    raise ValueError('Sink identity disagrees with its visible OUT/OBS/DEAD label')
                if definition['kind'] == 'discard':
                    cells[key] = cell
                    continue
                if definition.get('type') == 'cipher_output' and row != rows-1:
                    raise ValueError('Final anchor must occupy the physical bottom output row')
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
                raise ValueError('Unknown manual glyph or sink without its local definition')
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
    declarations, covered, unused, fragments, visible_indices = {}, {}, {}, {}, set()
    for definition in records.values():
        if definition['kind'] != 'input':
            continue
        if definition['index'] in visible_indices:
            raise ValueError('Duplicate visible input word index')
        visible_indices.add(definition['index'])
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
        fragments.setdefault(index, []).append(definition)
        covered.setdefault(index, set()).update(selected)
        unused.setdefault(index, set()).update(absent)
    if sorted(declarations) != list(range(len(declarations))):
        raise ValueError('Missing native input declaration')
    for index, item in declarations.items():
        ordered = sorted(fragments[index], key=lambda definition: definition['index'])
        indices = [definition['index'] for definition in ordered]
        positions = [bit for definition in ordered for bit in definition['positions']]
        if len(set(indices)) != len(indices) or positions != sorted(covered[index]) or len(positions) != len(covered[index]):
            raise ValueError('Input fragments disagree with visible word index order')
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


def _fragment_groups(cells):
    groups = {}
    for key, cell in cells.items():
        definition = cell.get('definition', {})
        if definition.get('kind') == 'native_fragment':
            if set(definition) != FIELDS['native_fragment']:
                raise ValueError('Incomplete native word fragment definition')
            groups.setdefault(definition['ordinal'], []).append((key, definition))
    for cell in cells.values():
        definition = cell.get('definition', {})
        if definition.get('kind') in ('native', 'native_boundary') and definition['ordinal'] in groups:
            raise ValueError('Native word fragment group collides with another native operation')
    for fragments in groups.values():
        first = fragments[0][1]
        if first['type'] != 'word_operation' or first['description'][0] not in ('XOR', 'AND', 'OR', 'NOT'):
            raise ValueError('Only independent bitwise words admit native fragments')
        widths = set()
        coverage = []
        for _, definition in fragments:
            if any(definition.get(field) != first.get(field) for field in (*NODE_FIELDS, 'operand_positions')):
                raise ValueError('Native word fragments disagree about their operation')
            positions = definition['positions']
            if not isinstance(positions, list) or not positions or any(type(bit) is not int or bit < 0 for bit in positions) or positions != list(range(positions[0], positions[0]+len(positions))):
                raise ValueError('Native word fragment positions must be ordered contiguous words')
            widths.add(len(positions));coverage.extend(positions)
        if len(widths) != 1 or sorted(coverage) != list(range(first['bits'])):
            raise ValueError('Native word fragments must cover every output bit exactly once')
    return groups


def _fragment_native(fragments, memo, native):
    definition = fragments[0][1]
    if definition['ordinal'] in native:
        return
    arity = definition['input_bits']//definition['bits']
    operands = [[] for _ in range(arity)]
    for key, fragment in sorted(fragments, key=lambda item: item[1]['positions'][0]):
        ports = fragment['operand_ports']
        if len(ports) != arity:
            raise ValueError('Native word fragment arity disagrees with visible ports')
        for index, port in enumerate(ports):
            stream = memo[parser._adjacent(key, port)]
            if len(parser._flat_stream([stream])) != len(fragment['positions']):
                raise ValueError('Native word fragment width disagrees with actual input')
            operands[index].extend(stream)
    parser._native_node(definition, definition, operands, parser._flat_stream(operands), native)


def _trace(cells, groups):
    dependencies, followers = {}, {}
    fragments = _fragment_groups(cells)
    for key, cell in cells.items():
        definition = cell.get('definition')
        for side, direction in cell['ports'].items():
            if direction != 'out':
                continue
            token = key, side
            if definition and definition['kind'] == 'native_boundary':
                incoming = ([parser._adjacent(key, 'top')] if definition.get('flow') == 'observe'
                            else _group_inputs(groups[definition['ordinal']]))
            elif definition and definition['kind'] == 'native_fragment':
                incoming = [parser._adjacent(fragment_key, port) for fragment_key, local in fragments[definition['ordinal']] for port in local['operand_ports']]
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
            if definition.get('flow') != 'observe':
                _boundary_native(groups[definition['ordinal']], memo, native)
            if definition.get('flow') == 'observe':
                stream = memo[parser._adjacent(token[0], 'top')]
            elif definition.get('flow', 'alias') == 'alias':
                stream = [{'source': definition['id'], 'positions': definition['positions']}]
            else:
                raise ValueError('Invalid observation flow role')
        elif definition and definition['kind'] == 'native_fragment':
            _fragment_native(fragments[definition['ordinal']], memo, native)
            stream = [{'source': definition['id'], 'positions': definition['positions']}]
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
    for key, cell in cells.items():
        definition = cell.get('definition', {})
        if definition.get('kind') == 'discard':
            incoming = parser._flat_stream([memo[parser._adjacent(key, 'top')]])
            if len(incoming) != definition['bits']:
                raise ValueError('Discard width disagrees with its actual visible input')
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
