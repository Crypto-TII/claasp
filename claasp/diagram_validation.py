"""Validation of local native transforms and ordered graph connectivity."""
import re
import copy
import operator

SCHEMA = 'claasp-diagrams/1'


def _ordered_native_value(value, depth=0):
    if depth > 64:
        raise ValueError('Native description nesting exceeds 64 levels')
    if type(value) in (str, int, bool, type(None)):
        return copy.deepcopy(value)
    try:
        return operator.index(value)
    except TypeError:
        pass
    unordered = isinstance(value, (dict, set, frozenset, bytes))
    if not unordered and hasattr(value, '__len__') and hasattr(value, '__getitem__'):
        return [_ordered_native_value(entry, depth+1) for entry in value]
    return copy.deepcopy(value)


def _binary_native_rows(rows):
    for row in rows:
        if not isinstance(row, list):
            continue
        for index, entry in enumerate(row):
            if type(entry) not in (int, bool) and entry in (0, 1):
                row[index] = int(entry)
    return rows


def _native_description(kind, value):
    """Canonical ordered native containers; exact binary entries only for binary maps."""
    result = _ordered_native_value(value)
    if kind == 'linear_layer' and isinstance(result, list):
        result = _binary_native_rows(result)
    return result


def _integer(value):
    return type(value) is int and abs(value) <= 2**53 - 1


def _word_operation(node):
    description = node['description']
    if not description:
        return False
    name = description[0]
    validators = {
        'XOR': _logical_word, 'AND': _logical_word, 'OR': _logical_word,
        'MODADD': _modular_word, 'MODSUB': _modular_word, 'MODMUL': _modular_word,
        'ROTATE': _fixed_parameter_word, 'SHIFT': _fixed_parameter_word,
        'NOT': _unary_word, 'REVERSE': _unary_word,
    }
    validator = validators.get(name)
    return validator is not None and validator(node)


def _arity(node, length):
    description = node['description']
    return (len(description) == length and _integer(description[1])
            and description[1] >= 1 and node['input_bits'] == description[1]*node['bits'])


def _logical_word(node):
    return _arity(node, 2)


def _modular_word(node):
    if not _arity(node, 3):
        return False
    modulus = node['description'][2]
    return modulus is None or (_integer(modulus) and modulus > 0)


def _fixed_parameter_word(node):
    description = node['description']
    return len(description) == 2 and _integer(description[1]) and node['input_bits'] == node['bits']


def _unary_word(node):
    description = node['description']
    return (len(description) == 2 and type(description[1]) is int
            and description[1] == 0 and node['input_bits'] == node['bits'])


def _constant(node):
    description = node['description']
    if node['input_bits'] != 0 or len(description) != 1:
        return False
    literal = description[0]
    if not isinstance(literal, str) or re.fullmatch(r'0x[0-9a-f]+', literal, re.I) is None:
        return False
    return int(literal, 16) < 2**node['bits']


def _output(node):
    description = node['description']
    return node['input_bits'] == node['bits'] and len(description) == 1 and isinstance(description[0], str)


def _sbox(node):
    if node['input_bits'] > 20:
        return False
    description = node['description']
    return (len(description) == 2**node['input_bits']
            and all(_integer(value) and 0 <= value < 2**node['bits'] for value in description))


def _permutation(node):
    description = node['description']
    if len(description) != 2 or not isinstance(description[0], list):
        return False
    positions, width = description
    if not _integer(width) or width <= 0:
        return False
    return (node['input_bits'] == node['bits'] and node['bits'] % width == 0
            and len(positions) == node['bits']//width
            and all(_integer(value) for value in positions)
            and sorted(positions) == list(range(len(positions))))


def _binary_row(row, bits):
    return isinstance(row, list) and len(row) == bits and all(type(value) is int and value in (0, 1) for value in row)


def _linear_layer(node):
    return len(node['description']) == node['input_bits'] and all(_binary_row(row, node['bits']) for row in node['description'])


def _field_parameters(polynomial, width):
    if not _integer(width) or not 1 <= width <= 52:
        return False
    if not _integer(polynomial) or polynomial < 0:
        return False
    return polynomial == 0 or 2**width <= polynomial < 2**(width + 1)


def _field_row(row, columns, polynomial, width):
    if not isinstance(row, list) or len(row) != columns:
        return False
    return all(_integer(value) and (polynomial == 0 or 0 <= value < 2**width) for value in row)


def _mix_column(node):
    description = node['description']
    if len(description) != 3:
        return False
    matrix, polynomial, width = description
    if not _field_parameters(polynomial, width):
        return False
    if node['input_bits'] % width or node['bits'] % width:
        return False
    return (isinstance(matrix, list) and len(matrix) == node['bits']//width
            and all(_field_row(row, node['input_bits']//width, polynomial, width) for row in matrix))


_TRANSFORMS = {
    'word_operation': _word_operation, 'constant': _constant,
    'intermediate_output': _output, 'cipher_output': _output,
    'sbox': _sbox, 'permutation': _permutation,
    'linear_layer': _linear_layer, 'mix_column': _mix_column,
}


def validate_native_component(node):
    """Reject unsupported or inconsistent local operation descriptions."""
    validator = _TRANSFORMS.get(node['type'])
    if validator is None or not validator(node):
        raise ValueError(f"Invalid or unsupported native {node['type']} description/width: {node['id']}")


def _input_widths(inputs):
    known = {}
    for item in inputs:
        if item['id'] in known or type(item['bits']) is not int or item['bits'] <= 0:
            raise ValueError('Invalid or duplicate input')
        known[item['id']] = item['bits']
    return known


def _node_header(node, known, last_round):
    positive_width = type(node['bits']) is int and node['bits'] > 0
    ordered_round = type(node['round']) is int and node['round'] >= 0 and node['round'] >= last_round
    input_width = type(node['input_bits']) is int and node['input_bits'] >= 0
    if node['id'] in known or not positive_width or not ordered_round or not input_width or not isinstance(node['description'], list):
        raise ValueError('Invalid node identity, width or round order')


def _positions(positions, width):
    return isinstance(positions, list) and all(type(bit) is int and 0 <= bit < width for bit in positions)


def _node_operands(node, known):
    total = 0
    for edge in node['operands']:
        if edge['source'] not in known:
            raise ValueError('Unknown, forward or cyclic bit link')
        if not _positions(edge['positions'], known[edge['source']]):
            raise ValueError('Invalid bit selection')
        total += len(edge['positions'])
    if total != node['input_bits']:
        raise ValueError('Input width disagrees with ordered bit links')


def validate(ir):
    """Validate ordered native definitions without modifying their representation."""
    if ir.get('schema') != SCHEMA:
        raise ValueError('Unsupported diagram schema')
    if type(ir.get('output_bits')) is not int or ir['output_bits'] <= 0:
        raise ValueError('Missing or invalid output width')
    known = _input_widths(ir['inputs'])
    last_round = -1
    for node in ir['nodes']:
        _node_header(node, known, last_round)
        _node_operands(node, known)
        validate_native_component(node)
        known[node['id']] = node['bits']
        last_round = node['round']
    outputs = [node for node in ir['nodes'] if node['type'] == 'cipher_output']
    if len(outputs) != 1 or outputs[0]['bits'] != ir['output_bits']:
        raise ValueError('Require one explicitly sized native cipher output')
    if type(ir['rounds']) is not int or ir['rounds'] <= 0 or last_round >= ir['rounds']:
        raise ValueError('Round outside declared range')
    return ir
