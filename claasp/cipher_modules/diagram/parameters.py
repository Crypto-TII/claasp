"""Visible parameter-only legends; no source IDs or dependency records."""

import re

START = '\n# CLAASP-HUMAN-PARAMETERS 1\n'
END = '\n# END CLAASP-HUMAN-PARAMETERS'


def facts(definition):
    """Return exact typed parameter facts, preserving literal spelling."""
    if definition.get('type') == 'constant':
        if not re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|0[bB][01]+)', definition['description'][0]):
            raise ValueError('Parameter legend v1 requires an explicit hexadecimal or binary literal')
        return 'CONST', definition['bits'], 'literal', definition['description'][0]
    description = definition.get('description', [])
    if (
        definition.get('type') == 'word_operation'
        and description[0] in ('MODADD', 'MODSUB', 'MODMUL')
        and description[2] is not None
    ):
        if description[2] > 9007199254740991:
            raise ValueError('Parameter legend v1 modulus exceeds the interoperable exact integer range')
        return description[0], definition['bits'], 'modulus', description[2]
    raise ValueError('Parameter reference requires an admitted constant or explicit modulus')


def reference(number):
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digits = ''
    while True:
        digits = alphabet[number % 36] + digits
        number //= 36
        if not number:
            break
    tag = 'P' + digits
    if len(tag) > 7:
        raise ValueError('Visible parameter reference exceeds manual capacity')
    return tag


def valid_reference(tag):
    if not isinstance(tag, str) or not re.fullmatch(r'P[0-9A-Z]{1,6}', tag):
        raise ValueError('Invalid visible parameter reference')
    if reference(int(tag[1:], 36)) != tag:
        raise ValueError('Noncanonical visible parameter reference')


def assignments(ir):
    by_facts, by_ordinal = {}, {}
    for ordinal, node in enumerate(ir['nodes']):
        description = node['description']
        long_constant = node['type'] == 'constant' and len('x' + format(int(description[0], 0), 'X')) > 14
        explicit_modulus = (
            node['type'] == 'word_operation'
            and description[0] in ('MODADD', 'MODSUB', 'MODMUL')
            and description[2] is not None
        )
        if long_constant or explicit_modulus:
            parameter = facts(node)
            if parameter not in by_facts:
                by_facts[parameter] = reference(len(by_facts))
            by_ordinal[ordinal] = by_facts[parameter]
    return by_ordinal


def serialize(records):
    definitions = {}
    for definition in records:
        if 'parameter_ref' not in definition:
            continue
        tag = definition['parameter_ref']
        valid_reference(tag)
        parameter = facts(definition)
        if tag in definitions and definitions[tag] != parameter:
            raise ValueError('Contradictory parameter reference')
        definitions[tag] = parameter
    if not definitions:
        return ''
    lines = [
        f'{tag} {op} bits={bits} {field}={value}'
        for tag, (op, bits, field, value) in sorted(definitions.items(), key=lambda item: int(item[0][1:], 36))
    ]
    return START + '\n'.join(lines) + END


def _entry(line):
    """Read one ASCII parameter entry without changing literal spelling."""
    tokens = line.split(' ')
    if len(tokens) != 4:
        raise ValueError('Invalid visible parameter definition')
    tag, operation, encoded_width, encoded_value = tokens
    width_match = re.fullmatch(r'bits=([1-9]\d*)', encoded_width, flags=re.ASCII)
    value_match = re.fullmatch(
        r'literal=(?:0[xX][\da-fA-F]+|0[bB][01]+)|modulus=[1-9]\d*', encoded_value, flags=re.ASCII
    )
    if (
        not re.fullmatch(r'P[0-9A-Z]{1,6}', tag)
        or operation not in ('CONST', 'MODADD', 'MODSUB', 'MODMUL')
        or not width_match
        or not value_match
    ):
        raise ValueError('Invalid visible parameter definition')
    valid_reference(tag)
    return tag, operation, width_match.group(1), encoded_value


def _entry_value(operation, width, encoded_value):
    bits = int(width)
    if bits > 2000000:
        raise ValueError('Visible parameter width exceeds bounds')
    field, spelling = encoded_value.split('=')
    if (operation == 'CONST') != (field == 'literal'):
        raise ValueError('Parameter kind disagrees with visible operation')
    if field == 'literal':
        if int(spelling, 0).bit_length() > bits:
            raise ValueError('Visible literal exceeds its width')
        value = spelling
    else:
        value = int(spelling)
        if value > 9007199254740991:
            raise ValueError('Parameter legend v1 modulus exceeds the interoperable exact integer range')
    return operation, bits, field, value


def split(body):
    if START not in body:
        if '# CLAASP-HUMAN-PARAMETERS' in body or '# END CLAASP-HUMAN-PARAMETERS' in body:
            raise ValueError('Malformed parameter legend framing')
        return body, {}
    if body.count(START) != 1 or not body.endswith(END):
        raise ValueError('Malformed parameter legend framing')
    grid, text = body.split(START)
    definitions = {}
    for line in text[: -len(END)].split('\n'):
        tag, operation, width, encoded_value = _entry(line)
        if tag in definitions:
            raise ValueError('Duplicate visible parameter definition')
        definitions[tag] = _entry_value(operation, width, encoded_value)
    return grid, definitions


def verify(records, definitions):
    used = set()
    for definition in records:
        if 'parameter_ref' not in definition:
            continue
        tag = definition['parameter_ref']
        valid_reference(tag)
        if tag not in definitions or facts(definition) != definitions[tag]:
            raise ValueError('Visible parameter disagrees with local native definition')
        used.add(tag)
    if used != set(definitions):
        raise ValueError('Unused visible parameter definition')
