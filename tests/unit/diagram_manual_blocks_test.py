import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, to_cipher, from_ascii
from claasp.cipher_modules.diagram.manual_blocks import encode, decode, MARKER


def toy():
    c = Cipher('anonymous', 'permutation', ['a', 'b'], [4, 4], 8)
    c.add_round()
    node = c.add_xor_component(['a', 'b'], [list(range(4))]*2, 4)
    c.add_cipher_output_component([node.id, 'b'], [list(range(4))]*2, 8)
    return from_cipher(c, roles={'b': 'key'})


def masked(alias=False):
    if alias:
        c = Cipher('anonymous_alias', 'permutation', ['a', 'b'], [4, 4], 8)
        c.add_round()
        x = c.add_xor_component(['a', 'b'], [list(range(4))]*2, 4)
        state = c.add_intermediate_output_component([x.id], [list(range(4))], 4, 'state')
        n = c.add_not_component([state.id], [list(range(4))], 4)
        c.add_cipher_output_component([n.id, x.id], [list(range(4))]*2, 8)
    else:
        c = Cipher('anonymous_mask', 'permutation', ['a', 'b', 'unused'], [8, 4, 4], 4)
        c.add_round()
        x = c.add_xor_component(['a', 'b'], [[0, 2, 5, 7], [3, 2, 1, 0]], 4)
        c.add_cipher_output_component([x.id], [list(range(4))], 4)
    return from_cipher(c, roles={'b': 'key'})


def framing(text):
    body, footer = text.split(MARKER)
    return body, json.loads(footer)


def altered(body, footer):
    return body+MARKER+json.dumps(footer)+'\n'


def test_manual_body_and_annotated_repeated_round_trips():
    ir = toy()
    before = copy.deepcopy(ir)
    body = encode(ir)
    assert MARKER not in body and '^' in body and 'S  I2' in body
    for _ in range(3):
        text = encode(ir, annotations=True)
        assert framing(text)[0] == body
        ir = from_ascii(text)
        assert ir == before
    assert toy() == before


def test_actual_glyph_and_wire_mutations_are_not_hidden_by_annotations():
    text = encode(toy(), annotations=True)
    body, footer = framing(text)
    for changed in (body.replace('^', '&', 1), body.replace('o', '+', 1), body.replace('<-----', '<     ', 1), body.replace('S  I2', '|  I2', 1)):
        assert changed != body
        with pytest.raises(ValueError):
            decode(altered(changed, footer))


def test_selection_masks_and_unused_declarations_have_independent_oracle():
    ir = masked()
    text = encode(ir, annotations=True, word_bits=4)
    recovered = decode(text)
    assert recovered == ir
    compiled = to_cipher(recovered)
    for a in range(256):
        for b in (0, 1, 7, 15):
            selected = 0
            for position in (0, 2, 5, 7):
                selected = (selected << 1) | ((a >> (7-position)) & 1)
            reverse_b = int(format(b, '04b')[::-1], 2)
            assert compiled.evaluate([a, b, 7]) == selected ^ reverse_b
    body, footer = framing(text)
    unused = next(r['definition'] for r in footer['records'] if r['definition'].get('unused_positions'))
    unused['unused_positions'].pop()
    with pytest.raises(ValueError, match='every bit'):
        decode(altered(body, footer))


def test_local_mask_change_changes_parsed_computation():
    text = encode(masked(), annotations=True, word_bits=4)
    body, footer = framing(text)
    definition = next(r['definition'] for r in footer['records'] if r['definition']['kind'] == 'selection' and len(r['definition']['positions']) == 4 and r['definition']['positions'][0] == 0)
    definition['positions'][0] = 1
    original = to_cipher(decode(text))
    changed = to_cipher(decode(altered(body, footer)))
    assert original.evaluate([128, 0, 0]) != changed.evaluate([128, 0, 0])


def test_observation_alias_keeps_original_branch_and_native_identity():
    ir = masked(alias=True)
    recovered = decode(encode(ir, annotations=True))
    assert recovered == ir
    assert recovered['nodes'][2]['operands'][0]['source'] == recovered['nodes'][1]['id']
    assert recovered['nodes'][3]['operands'][1]['source'] == recovered['nodes'][0]['id']
    compiled = to_cipher(recovered)
    for a in range(16):
        for b in range(16):
            value = a ^ b
            assert compiled.evaluate([a, b]) == ((15 ^ value) << 4) | value


def test_noncommutative_order_with_reversed_declared_inputs():
    c = Cipher('anonymous_subtract', 'permutation', ['a', 'b'], [4, 4], 4)
    c.add_round()
    node = c.add_modsub_component(['b', 'a'], [list(range(4))]*2, 4)
    c.add_cipher_output_component([node.id], [list(range(4))], 4)
    ir = from_cipher(c)
    text = encode(ir, annotations=True)
    assert decode(text) == ir
    compiled = to_cipher(decode(text))
    assert compiled.evaluate([3, 7]) == 4
    body, footer = framing(text)
    definition = next(r['definition'] for r in footer['records'] if r['definition']['kind'] == 'native')
    definition['operand_ports'].reverse()
    with pytest.raises(ValueError, match='Noncommutative'):
        decode(altered(body, footer))


@pytest.mark.parametrize('field', ['source', 'operands', 'nodes', 'output_values', 'original_graph'])
def test_hidden_dependency_annotations_are_rejected(field):
    body, footer = framing(encode(toy(), annotations=True))
    footer['records'][0]['definition'][field] = []
    with pytest.raises(ValueError, match='Hidden dependency'):
        decode(altered(body, footer))


def test_identifier_renaming_does_not_change_manual_body():
    original = toy()
    renamed = copy.deepcopy(original)
    mapping = {item['id']: 'opaque'+str(index) for index, item in enumerate(original['inputs']+original['nodes'])}
    for item in renamed['inputs']+renamed['nodes']:
        item['id'] = mapping[item['id']]
    for node in renamed['nodes']:
        for edge in node['operands']:
            edge['source'] = mapping[edge['source']]
    assert encode(original) == encode(renamed)
    assert decode(encode(renamed, annotations=True)) == renamed


def branching():
    c = Cipher('anonymous_branching', 'permutation', ['a', 'b', 'c'], [4]*3, 8)
    c.add_round()
    values = ['a', 'b', 'c']
    operations = [('xor', 0, 2), ('modadd', 2, 0), ('modadd', 2, 4), ('xor', 1, 4),
                  ('xor', 4, 5), ('and', 6, 5), ('modadd', 8, 5), ('and', 7, 8),
                  ('and', 0, 10), ('and', 7, 5), ('xor', 6, 8), ('xor', 8, 2)]
    for operation, first, second in operations:
        node = getattr(c, 'add_'+operation+'_component')([values[first], values[second]], [list(range(4))]*2, 4)
        values.append(node.id)
    c.add_cipher_output_component(values[-2:], [list(range(4))]*2, 8)
    return from_cipher(c)


def test_generic_layout_preferences_expose_real_cost_tradeoff():
    from claasp.cipher_modules.diagram.manual_blocks import build
    ir = branching()
    width = build(ir, layout_preference='width')[1]
    depth = build(ir, layout_preference='depth')[1]
    assert depth['metrics']['depth'] < width['metrics']['depth']
    assert width['metrics']['width'] < depth['metrics']['width']
    assert depth['selected_variant'] != width['selected_variant']
    for preference in ('balanced', 'crossings', 'depth', 'width'):
        assert decode(encode(ir, annotations=True, layout_preference=preference)) == ir


def test_alignment_changes_real_geometry_but_preserves_output_anchors():
    ir = branching()
    left = encode(ir, annotations=True, alignment='left')
    right = encode(ir, annotations=True, alignment='right')
    assert framing(left)[0] != framing(right)[0]
    for text in (left, right):
        assert decode(text) == ir
        for record in framing(text)[1]['records']:
            if record['definition'].get('type') == 'cipher_output':
                assert record['col'] == record['definition']['positions'][0]//4


@pytest.mark.parametrize('strategy', ['semantic-legacy', 'semantic-ports', 'semantic-round', 'semantic-width', 'semantic-depth', 'semantic-crossings', 'direct-bus'])
def test_every_generic_schedule_keeps_fresh_native_semantics(strategy):
    ir = masked(alias=True)
    assert decode(encode(ir, annotations=True, strategy=strategy)) == ir


@pytest.mark.parametrize('options', [{'alignment':'bad'}, {'layout_preference':'bad'}, {'strategy':'by-cipher-name'}, {'max_calls':1}, {'max_cells':1}, {'max_grid_area':1}, {'max_text_bytes':1}, {'wire_borders':1}])
def test_real_controls_and_work_bounds_reject_invalid_requests(options):
    with pytest.raises(ValueError):
        encode(toy(), **options)


def test_wire_border_option_uses_supported_manual_vocabulary():
    ir = toy()
    plain = encode(ir, annotations=True, wire_borders=False)
    framed = encode(ir, annotations=True, wire_borders=True)
    assert framing(plain)[0] != framing(framed)[0]
    assert decode(plain) == decode(framed) == ir


def test_readable_cue_mutation_is_checked_against_local_definitions():
    text = encode(toy(), annotations=True)
    body, footer = framing(text)
    assert 'KEY2' in body
    with pytest.raises(ValueError, match='legend/stage'):
        decode(altered(body.replace('KEY2', 'KEY1', 1), footer))


def test_dynamic_ready_frontier_does_not_retain_consumed_chain_calls(monkeypatch):
    from claasp.cipher_modules.diagram.manual_blocks import _Scheduler
    observed = []
    original = _Scheduler.next_call
    def check_frontier(self):
        observed.append(len(self.ready_calls.eligible))
        return original(self)
    monkeypatch.setattr(_Scheduler, 'next_call', check_frontier)
    c = Cipher('generic_chain', 'permutation', ['a','b'], [4,4], 4)
    c.add_round(); value = 'a'
    for _ in range(96):
        value = c.add_xor_component([value,'b'], [list(range(4))]*2, 4).id
    c.add_cipher_output_component([value], [list(range(4))], 4)
    ir = from_cipher(c)
    assert decode(encode(ir,annotations=True,strategy='semantic-width')) == ir
    assert max(observed) <= 2
