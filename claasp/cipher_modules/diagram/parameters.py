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
    if definition.get('type') == 'word_operation' and description[0] in ('MODADD', 'MODSUB', 'MODMUL') and description[2] is not None:
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
        explicit_modulus = node['type'] == 'word_operation' and description[0] in ('MODADD', 'MODSUB', 'MODMUL') and description[2] is not None
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
    lines = [f'{tag} {op} bits={bits} {field}={value}'
             for tag, (op, bits, field, value) in sorted(definitions.items(), key=lambda item: int(item[0][1:], 36))]
    return START + '\n'.join(lines) + END


def split(body):
    if START not in body:
        if '# CLAASP-HUMAN-PARAMETERS' in body or '# END CLAASP-HUMAN-PARAMETERS' in body:
            raise ValueError('Malformed parameter legend framing')
        return body, {}
    if body.count(START) != 1 or not body.endswith(END):
        raise ValueError('Malformed parameter legend framing')
    grid, text = body.split(START)
    definitions = {}
    for line in text[:-len(END)].split('\n'):
        match = re.fullmatch(r'(P[0-9A-Z]{1,6}) (CONST|MODADD|MODSUB|MODMUL) bits=([1-9][0-9]*) (literal=(?:0[xX][0-9a-fA-F]+|0[bB][01]+)|modulus=[1-9][0-9]*)', line)
        if not match:
            raise ValueError('Invalid visible parameter definition')
        tag, op, width, value = match.groups()
        valid_reference(tag)
        if tag in definitions:
            raise ValueError('Duplicate visible parameter definition')
        bits = int(width)
        if bits > 2000000:
            raise ValueError('Visible parameter width exceeds bounds')
        field, spelling = value.split('=')
        if (op == 'CONST') != (field == 'literal'):
            raise ValueError('Parameter kind disagrees with visible operation')
        if field == 'literal' and int(spelling, 0).bit_length() > bits:
            raise ValueError('Visible literal exceeds its width')
        definitions[tag] = op, bits, field, spelling if field == 'literal' else int(spelling)
        if field == 'modulus' and definitions[tag][3] > 9007199254740991:
            raise ValueError('Parameter legend v1 modulus exceeds the interoperable exact integer range')
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
