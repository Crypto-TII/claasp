"""Generic aligned-word presentation, separate from typed audit serialization."""
from collections import Counter
from functools import reduce
from math import gcd


def _word_size(ir, requested):
    widths = [n['bits'] for n in ir['nodes'] if n['type'] == 'word_operation']
    bits = reduce(gcd, widths or [ir['output_bits']]) if requested is None else requested
    if type(bits) is not int or bits < 1:
        raise ValueError('Supply a positive word_bits')
    if any(i['bits'] % bits for i in ir['inputs']):
        raise ValueError('Inputs do not identify uniform aligned words; use the typed audit view')
    return bits


def _words(operands, values, bits):
    result = []
    for edge in operands:
        positions = edge['positions']
        if len(positions) % bits:
            raise ValueError('Partial-word selection needs the typed audit view')
        for start in range(0, len(positions), bits):
            selected = positions[start:start+bits]
            first = selected[0]
            if first % bits or selected != list(range(first, first+bits)):
                raise ValueError('Noncontiguous selection needs the typed audit view')
            result.append(values[edge['source']][first//bits])
    return result


def _lower(ir, bits):
    inputs, values, events, outputs = [], {}, [], []
    for item in ir['inputs']:
        words = [(item['id'], index) for index in range(item['bits']//bits)]
        values[item['id']] = words
        inputs.extend((word, f"{item['id']}[{word[1]}]", item['role']) for word in words)
    for node in ir['nodes']:
        args = _words(node['operands'], values, bits)
        if node['type'] in ('cipher_output', 'intermediate_output'):
            values[node['id']] = args
            if node['type'] == 'cipher_output':
                outputs = args
            else:
                events.append(('observe', node, args))
        elif node['type'] == 'word_operation' and node['bits'] == bits:
            op = node['description'][0]
            if op not in ('ROTATE', 'SHIFT', 'NOT', 'REVERSE', 'XOR', 'AND', 'OR', 'MODADD', 'MODSUB', 'MODMUL', 'IDEA_MODMUL'):
                raise ValueError('This operation needs the typed audit view')
            unary = op in ('ROTATE', 'SHIFT', 'NOT', 'REVERSE')
            if len(args) != (1 if unary else 2):
                raise ValueError('Human word view currently needs unary or binary word operations')
            value = (node['id'], 0)
            values[node['id']] = [value]
            events.append(('operation', node, args))
        elif node['type'] == 'constant' and node['bits'] == bits:
            value = (node['id'], 0)
            values[node['id']] = [value]
            events.append(('operation', node, []))
        else:
            raise ValueError('This word projection is ambiguous; use the typed audit view')
    return inputs, events, outputs


def _operation_label(node, style):
    d = node['description']
    if node['type'] == 'constant':
        return d[0]
    op = d[0]
    if op in ('ROTATE', 'SHIFT'):
        amount = d[1]
        if style == 'labels':
            if op == 'ROTATE':
                label = 'ROL' if amount < 0 else 'ROR'
            else:
                label = 'SHL' if amount < 0 else 'SHR'
        elif op == 'ROTATE':
            label = '<<<' if amount < 0 else '>>>'
        else:
            label = '<<' if amount < 0 else '>>'
        return label+str(abs(amount))
    symbols = {'XOR': '^', 'AND': '&', 'OR': '|', 'NOT': '~', 'REVERSE': 'REV',
               'MODADD': '+', 'MODSUB': '-', 'MODMUL': '*', 'IDEA_MODMUL': 'MAP*'}
    label = op if style == 'labels' else symbols.get(op, op)
    if op in ('MODADD', 'MODSUB', 'MODMUL', 'IDEA_MODMUL') and len(d) > 2 and d[2] is not None:
        label += ' mod '+str(d[2])
    return label


class _WordDrawing:
    def __init__(self, inputs, events, outputs, pitch, alignment, style, borders, max_area):
        self.inputs, self.events, self.outputs = inputs, events, outputs
        self.pitch, self.alignment, self.style, self.borders = pitch, alignment, style, borders
        self.uses = Counter(word for _, _, args in events for word in args)
        self.uses.update(outputs)
        used = [item for item in inputs if self.uses[item[0]]]
        self.unused = [label for word, label, role in inputs if not self.uses[word]]
        self.slots = {word: i for i, (word, _, _) in enumerate(used)}
        self.active = {self.slots[word] for word in self.slots if self.uses[word]}
        self.maximum = max(0, len(self.slots)-1)
        self.lines, self.notes = [], []
        self.max_area = max_area

    def center(self, col):
        return col*self.pitch+self.pitch//2

    def line(self):
        result = [' ']*((self.maximum+1)*self.pitch)
        for col in self.active:
            result[self.center(col)] = '|'
        return result

    def text(self, line, col, label):
        maximum = self.pitch-2
        if len(label) > maximum:
            label = label[:maximum-1]+'~'
        start = self.center(col)-len(label)//2
        line[start:start+len(label)] = label

    def append(self, line):
        if (len(self.lines)+1)*len(line) > self.max_area:
            raise ValueError('Human presentation exceeds max_grid_area/max_cells')
        self.lines.append(''.join(line).rstrip())

    def target(self, args):
        eligible = [self.slots[a] for a in args if self.uses[a] == args.count(a)]
        if eligible:
            return min(eligible) if self.alignment == 'left' else max(eligible)
        if args:
            lanes = [self.slots[arg] for arg in args]
            return min(lanes) if self.alignment == 'left' else max(lanes)
        free = [i for i in range(self.maximum+2) if i not in self.active]
        near = 0
        target = min(free, key=lambda i: (abs(i-near), i))
        self.maximum = max(self.maximum, target)
        return target

    def operation(self, node, args):
        target = self.target(args)
        preserved = {}
        for arg in dict.fromkeys(args):
            if self.slots[arg] == target and self.uses[arg] > args.count(arg):
                free = next(i for i in range(self.maximum+2) if i not in self.active)
                self.route(target, free, True)
                preserved[arg] = free
        above, row = self.line(), self.line()
        ordered = node['type'] == 'word_operation' and node['description'][0] == 'MODSUB'
        for index, arg in enumerate(args, 1):
            source = self.slots[arg]
            if source == target:
                self.text(above, target, f'{index}v' if ordered else 'v')
                continue
            x, end = self.center(source), self.center(target)
            for pos in range(min(x, end)+1, max(x, end)):
                row[pos] = 'x' if row[pos] == '|' else '-'
            row[x] = 'o' if self.uses[arg] > args.count(arg) else ('/' if x > end else chr(92))
            row[end+1 if x > end else end-1] = '<' if x > end else '>'
            if ordered:
                row[end+2 if x > end else end-2] = str(index)
        self.append(above)
        label = _operation_label(node, self.style)
        if (len(label) > 1 and len(args) > 1) or self.borders:
            row[self.center(target)] = 'v'
            self.append(row)
            row = self.line()
        limit = self.pitch-4 if self.borders else self.pitch-2
        for start in range(0, len(label), limit):
            if start:
                row = self.line()
            part = label[start:start+limit]
            self.text(row, target, '['+part+']' if self.borders else part)
            self.append(row)
        for arg in args:
            self.uses[arg] -= 1
            if not self.uses[arg]:
                self.active.discard(self.slots.pop(arg))
        self.slots.update(preserved)
        value = (node['id'], 0)
        self.slots[value] = target
        if self.uses[value]:
            self.active.add(target)
        self.append(self.line())

    def route(self, source, target, remaining):
        """Route to an unused lane, distinguishing forks from crossings."""
        self.maximum = max(self.maximum, target)
        row = self.line()
        x, end = self.center(source), self.center(target)
        for position in range(min(x, end)+1, max(x, end)):
            row[position] = 'x' if row[position] == '|' else '-'
        row[x] = 'o' if remaining else ('/' if x > end else chr(92))
        row[end] = 'v'
        self.append(row)
        if not remaining:
            self.active.discard(source)
        self.active.add(target)
        self.append(self.line())

    def anchor_outputs(self):
        pending = list(range(len(self.outputs)))
        pinned = set()
        while pending:
            progress = False
            for index in list(pending):
                value = self.outputs[index]
                source = self.slots[value]
                if source == index:
                    pinned.add(index)
                elif index not in self.active:
                    other_uses = any(self.outputs[j] == value for j in pending if j != index)
                    self.route(source, index, source in pinned or other_uses)
                    if source not in self.active:
                        self.slots[value] = index
                    pinned.add(index)
                else:
                    continue
                pending.remove(index)
                progress = True
            if not progress:
                # Break a permutation cycle with one temporary live lane.
                value = self.outputs[pending[0]]
                source = self.slots[value]
                temporary = next(i for i in range(self.maximum+2) if i not in self.active)
                self.route(source, temporary, False)
                self.slots[value] = temporary

    def render(self):
        header = self.line()
        for word, label, role in self.inputs:
            if word not in self.slots:
                continue
            self.text(header, self.slots[word], ('S:' if role == 'key' else '')+label)
        self.append(header)
        self.append(self.line())
        previous_round = None
        for kind, node, args in self.events:
            if node['round'] != previous_round:
                row = self.line()
                label = f"r{node['round']}"
                row[:len(label)] = label
                self.append(row)
                previous_round = node['round']
            if kind == 'observe':
                names = [f'{source}[{index}]' for source, index in args]
                self.notes.append(f"round {node['round']}: {node['description'][0]} = "+', '.join(names))
                for arg in args:
                    self.uses[arg] -= 1
                    if not self.uses[arg]:
                        self.active.discard(self.slots.pop(arg))
            else:
                self.operation(node, args)
        self.anchor_outputs()
        bottom = self.line()
        for index, value in enumerate(self.outputs):
            self.text(bottom, index, f'out[{index}]')
        self.append(bottom)
        if self.unused:
            self.notes.insert(0, 'Declared inputs unused in this computation: '+', '.join(self.unused))
        return '\n'.join(self.lines), self.notes


def to_word_ascii(ir, *, word_bits=None, operator_style='symbols', borders=False,
                  alignment='left', column_spacing=18, max_grid_area=2000000):
    """Candidate human view. Exact typed serialization remains a separate API mode.

    Input names only label fixed-width lanes; they never choose a topology.
    Uniform aligned words are inferred from operation widths, not cipher names.
    """
    if operator_style not in ('symbols', 'labels') or alignment not in ('left', 'right'):
        raise ValueError('Choose symbols/labels and left/right operation alignment')
    if type(column_spacing) is not int or column_spacing < 16:
        raise ValueError('column_spacing must be at least 16 characters')
    from .validation import validate
    validate(ir)
    bits = _word_size(ir, word_bits)
    inputs, events, outputs = _lower(ir, bits)
    drawing, notes = _WordDrawing(inputs, events, outputs, column_spacing, alignment, operator_style, borders, max_grid_area).render()
    return f'{bits}-bit words; MSB-first input order; x crossing, o fork\n'+drawing+('\nDeclarations and observations:\n'+'\n'.join(notes) if notes else '')
