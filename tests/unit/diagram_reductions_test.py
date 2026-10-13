import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher
from claasp.cipher_modules.diagram.manual_blocks import MARKER, _encode_layout, art


def tree(operation='xor', observed=False):
    inputs = ['a', 'b', 'c', 'd', 'e'] if observed else ['a', 'b', 'c']
    c = Cipher('anonymous_reduction', 'permutation', inputs, [4]*len(inputs), 8 if observed else 4)
    c.add_round()
    ids = inputs if observed else ['a', 'b', 'c', 'a']
    x = getattr(c, 'add_'+operation+'_component')(ids, [list(range(4))]*len(ids), 4)
    if observed:
        obs = c.add_intermediate_output_component([x.id], [list(range(4))], 4, 'observed')
        c.add_round()
        y = c.add_not_component([obs.id], [list(range(4))], 4)
        c.add_cipher_output_component([x.id, y.id], [list(range(4))]*2, 8)
    else:
        c.add_cipher_output_component([x.id], [list(range(4))], 4)
    return from_cipher(c)


@pytest.mark.parametrize('operation', ['xor', 'and', 'or', 'modadd'])
def test_actual_ordered_tree_recovers_one_native_node_and_independent_arithmetic(operation):
    ir = tree(operation)
    with pytest.raises(ValueError, match='port arity'):
        to_ascii(ir, annotations=True, word_bits=4)
    text = to_ascii(ir, annotations=True, word_bits=4, associative_reductions=True)
    assert '.R0' in text
    assert '.R1' in text
    assert '.R2' in text
    actual = from_ascii(text)
    assert actual == ir
    assert len(actual['nodes']) == 2
    restored = to_cipher(actual)
    for a in range(16):
        for b in (0, 7, 15):
            for c in (0, 1, 15):
                expected = {'xor': a^b^c^a, 'and': a&b&c&a,
                            'or': a|b|c|a, 'modadd': (2*a+b+c)&15}[operation]
                assert restored.evaluate([a, b, c]) == expected
    for _ in range(3):
        text2 = to_ascii(actual, annotations=True, word_bits=4, associative_reductions=True)
        assert text2 == text
        actual = from_ascii(text2)
        assert actual == ir


def test_observation_and_reused_root_are_retained():
    ir = tree(observed=True)
    text = to_ascii(ir, annotations=True, word_bits=4, associative_reductions=True)
    assert from_ascii(text) == ir
    restored = to_cipher(from_ascii(text))
    for a in range(16):
        x = a^7^3^a^15
        assert restored.evaluate([a, 7, 3, a, 15]) == (x<<4)|(x^15)


def test_reduction_records_and_glyphs_cannot_conceal_changes():
    text = to_ascii(tree(), annotations=True, word_bits=4, associative_reductions=True)
    body, footer = text.split(MARKER)
    for mutation in (body.replace('.R0', '.R1', 1), body.replace('^', '&', 1)):
        assert mutation != body
        with pytest.raises(ValueError):
            from_ascii(mutation+MARKER+footer)
    metadata = json.loads(footer)
    definitions = [record['definition'] for record in metadata['records'] if record['definition']['kind'] == 'native_reduce']
    for field, value in [('bits', 8), ('step', 99), ('ordinal', 1), ('description', ['MODSUB', 4, None])]:
        edited = copy.deepcopy(metadata)
        next(record['definition'] for record in edited['records'] if record['definition']['kind'] == 'native_reduce')[field] = value
        malformed_text = body+MARKER+json.dumps(edited)
        with pytest.raises(ValueError):
            from_ascii(malformed_text)
    assert all(set(item) == {'kind','ordinal','id','type','bits','input_bits','round','description','operand_positions','operand_ports','step'} for item in definitions)


def test_subtraction_and_explicit_modulus_are_not_associatively_lowered():
    candidate_ir = tree('modsub')
    with pytest.raises(ValueError, match='R1 excludes'):
        to_ascii(candidate_ir, annotations=True, word_bits=4, associative_reductions=True)
    ir = tree('modadd')
    ir['nodes'][0]['description'][2] = 13
    with pytest.raises(ValueError, match='R1 excludes'):
        to_ascii(ir, annotations=True, word_bits=4, associative_reductions=True)
    candidate_ir = tree()
    with pytest.raises(ValueError, match='whole projection'):
        to_ascii(candidate_ir, annotations=True, word_bits=4, associative_reductions=True, projection='wordwise')


def test_consistent_identifier_renaming_leaves_actual_tree_body_unchanged():
    ir = tree()
    text = to_ascii(ir, annotations=True, word_bits=4, associative_reductions=True)
    renamed = copy.deepcopy(ir)
    mapping = {item['id']: 'input'+str(i) for i,item in enumerate(ir['inputs'])}
    mapping.update({item['id']: 'node'+str(i) for i,item in enumerate(ir['nodes'])})
    renamed['name'] = 'renamed'
    for item in renamed['inputs']: item['id'] = mapping[item['id']]
    for node in renamed['nodes']:
        node['id'] = mapping[node['id']]
        for edge in node['operands']: edge['source'] = mapping[edge['source']]
    other = to_ascii(renamed, annotations=True, word_bits=4, associative_reductions=True)
    assert other.split(MARKER)[0] == text.split(MARKER)[0]
    assert from_ascii(other) == renamed


def test_actual_visible_nonroot_observation_is_rejected():
    text, cells, report = _encode_layout(tree(), annotations=True, word_bits=4, associative_reductions=True)
    body, footer = text.split(MARKER)
    metadata = json.loads(footer)
    key = next(key for key, cell in cells.items() if cell.get('definition', {}).get('kind') == 'native_reduce' and cell['definition']['step'] == 0)
    row, col = key
    inserted = row+1
    definition = {'kind': 'native_boundary', 'ordinal': 2, 'id': 'observed_extra',
                  'type': 'intermediate_output', 'bits': 4, 'input_bits': 4,
                  'round': 0, 'description': ['extra'], 'operand_positions': [list(range(4))],
                  'operand_ports': ['top'], 'positions': list(range(4)), 'flow': 'observe'}
    glyphs = []
    for column in range(report['cols']):
        upper = cells.get((row, column), {})
        lower = cells.get((row+1, column), {})
        if upper.get('ports', {}).get('bottom') == 'out' and lower.get('ports', {}).get('top') == 'in':
            cell = {'kind': 'tap' if column == col else 'wire', 'ports': {'top':'in','bottom':'out'}, 'invisible':True}
            if column == col: cell['definition'] = definition
            glyphs.append(art(cell))
        else:
            glyphs.append([' '*11]*5)
    inserted_lines = [''.join(glyph[index] for glyph in glyphs) for index in range(5)]
    lines = body.split('\n'); lines[inserted*5:inserted*5] = inserted_lines
    for record in metadata['records']:
        if record['row'] >= inserted: record['row'] += 1
    metadata['records'].append({'row': inserted, 'col': col, 'definition': definition})
    malformed_text = '\n'.join(lines)+MARKER+json.dumps(metadata)
    with pytest.raises(ValueError, match='one actual routed root|Nonroot reduction result'):
        from_ascii(malformed_text)


def test_actual_selection_helpers_preserve_noncontiguous_repeated_bits():
    c = Cipher('anonymous_selected_reduction', 'permutation', ['a', 'b'], [8, 4], 4)
    c.add_round()
    x = c.add_xor_component(['a', 'b', 'a', 'a'],
                            [[0, 2, 2, 7], list(range(4)), [7, 6, 5, 4], [0, 2, 2, 7]], 4)
    c.add_cipher_output_component([x.id], [list(range(4))], 4)
    ir = from_cipher(c)
    text = to_ascii(ir, annotations=True, word_bits=4, associative_reductions=True)
    assert 'SEL' in text
    assert from_ascii(text) == ir
    restored = to_cipher(from_ascii(text))
    for a in range(256):
        reverse_low = sum(((a >> index)&1) << (3-index) for index in range(4))
        assert restored.evaluate([a, 7]) == 7 ^ reverse_low
