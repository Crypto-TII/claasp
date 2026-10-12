"""Reconstruct strict binary reduction trees from actual visible routes."""
from collections import Counter, namedtuple
from . import parser

Value = namedtuple('ReductionValue', 'ordinal step leaves')
ALLOWED = {'XOR', 'AND', 'OR', 'MODADD'}


def groups(cells, dependencies, node_fields, fields):
    result = {}
    for key, cell in cells.items():
        definition = cell.get('definition', {})
        if definition.get('kind') == 'native_reduce':
            if set(definition) != fields:
                raise ValueError('Incomplete native reduction definition')
            ordinal, step = definition['ordinal'], definition['step']
            if type(ordinal) is not int or ordinal < 0 or type(step) is not int or step < 0:
                raise ValueError('Invalid reduction group or step')
            members = result.setdefault(ordinal, {})
            if step in members:
                raise ValueError('Duplicate reduction member')
            members[step] = key, definition
    if not result:
        return {}
    for cell in cells.values():
        definition = cell.get('definition', {})
        if definition.get('kind') in ('native', 'native_fragment', 'native_boundary') and definition['ordinal'] in result:
            raise ValueError('Reduction group collides with another native kind')

    def producer(token):
        seen = set()
        while True:
            if token in seen or token not in dependencies:
                raise ValueError('Unresolved or circular reduction route')
            seen.add(token)
            cell = cells[token[0]]
            if cell.get('definition') or cell['kind'] == 'input':
                return token[0], cell.get('definition', {})
            incoming = dependencies[token]
            if len(incoming) != 1:
                raise ValueError('Reduction route must carry one actual stream')
            token = incoming[0]

    parents, external = Counter(), Counter()
    for key, cell in cells.items():
        consumer = cell.get('definition')
        if not consumer or consumer['kind'] == 'input':
            continue
        for side, direction in cell['ports'].items():
            if direction != 'in':
                continue
            _, source = producer(parser._adjacent(key, side))
            if source.get('kind') != 'native_reduce':
                continue
            member = source['ordinal'], source['step']
            if consumer.get('kind') == 'native_reduce' and consumer['ordinal'] == source['ordinal']:
                parents[member] += 1
            else:
                external[member] += 1
    output = {}
    for ordinal, members in result.items():
        first = next(iter(members.values()))[1]
        description = first['description']
        if first['type'] != 'word_operation' or description[0] not in ALLOWED:
            raise ValueError('Only associative admitted operations permit R1 reduction')
        if description[0] == 'MODADD' and description[2] is not None:
            raise ValueError('R1 reductions require an implicit modulus')
        arity = description[1]
        if type(arity) is not int or arity < 3 or first['input_bits'] != arity * first['bits'] or sorted(members) != list(range(arity - 1)):
            raise ValueError('Reduction membership disagrees with original arity and width')
        for key, definition in members.values():
            if any(definition.get(field) != first.get(field) for field in (*node_fields, 'operand_positions')):
                raise ValueError('Reduction members disagree about native fields')
            if len(definition['operand_ports']) != 2:
                raise ValueError('Each reduction member must have two ordered ports')
        roots = [step for step in members if parents[ordinal, step] == 0]
        if len(roots) != 1:
            raise ValueError('Reduction must have one actual routed root')
        root = roots[0]
        if any(parents[ordinal, step] != 1 or external[ordinal, step] for step in members if step != root):
            raise ValueError('Nonroot reduction result must have exactly one in-group consumer')
        output[ordinal] = {'members': members, 'root': root, 'seen': set()}
    return output


def stream(definition, arguments, groups, native):
    group = groups[definition['ordinal']]
    step = definition['step']
    leaves = []
    if len(arguments) != 2 or step in group['seen']:
        raise ValueError('Invalid reduction execution')
    for argument in arguments:
        if isinstance(argument, Value):
            if argument.ordinal != definition['ordinal']:
                raise ValueError('Intermediate reduction cannot cross groups')
            leaves.extend(argument.leaves)
        else:
            if len(parser._flat_stream([argument])) != definition['bits']:
                raise ValueError('Reduction leaf width disagrees with native width')
            leaves.extend(argument)
    group['seen'].add(step)
    if step != group['root']:
        return Value(definition['ordinal'], step, leaves)
    if group['seen'] != set(group['members']) or len(parser._flat_stream([leaves])) != definition['input_bits']:
        raise ValueError('Reduction root lacks complete ordered leaf coverage')
    return [parser._native_node(definition, definition, [leaves], parser._flat_stream([leaves]), native)]
