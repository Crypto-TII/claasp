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


def literal_ir(literal, width):
    c = Cipher('generic_literal', 'permutation', [], [], width)
    c.add_round()
    constant = c.add_constant_component(width, 0)
    c.add_cipher_output_component([constant.id], [list(range(width))], width)
    ir = from_cipher(c)
    ir['nodes'][0]['description'] = [literal]
    return ir


@pytest.mark.parametrize('literal,width,expected', [
    ('0b101', 8, 5), ('0b10001', 8, 17), ('0B000101', 8, 5),
    ('0x05', 8, 5), ('0X11', 8, 17), ('0x0000', 8, 0), ('0xff', 8, 255),
])
def test_visible_constant_value_is_independent_of_native_radix(literal, width, expected):
    import re
    from claasp.diagrams import to_ascii
    ir = literal_ir(literal, width)
    for style in ('symbols', 'labels'):
        body = to_ascii(ir, operator_style=style)
        # Decode the visible hexadecimal token independently, rather than
        # calling the native label formatter or using metadata as an oracle.
        tokens = re.findall(r'\|\s*x([0-9A-F]+)\s*\|', body)
        assert len(tokens) == 1 and int(tokens[0], 16) == expected
        assert 'xB101' not in body and 'xB10001' not in body
        recovered = decode(to_ascii(ir, operator_style=style, annotations=True))
        assert recovered['nodes'][0]['description'] == [literal]
        assert to_cipher(recovered).evaluate([]) == expected


@pytest.mark.parametrize('literal,width', [
    ('0b102', 8), ('0b', 8), ('0x', 8), ('0xGG', 8), ('17', 8),
    ('-0x1', 8), ('0b10000', 4), ('0x100', 8),
])
def test_invalid_and_overwide_literals_fail_before_rendering(literal, width):
    from claasp.diagrams import to_ascii
    with pytest.raises(ValueError, match='unsupported native constant'):
        to_ascii(literal_ir(literal, width))


def test_visible_binary_literal_mutation_cannot_hide_behind_metadata():
    text = encode(literal_ir('0b101',8), annotations=True)
    body, footer = framing(text)
    assert 'x5' in body
    with pytest.raises(ValueError, match='definition disagrees with visible glyph'):
        decode(altered(body.replace('x5', 'x6', 1), footer))


@pytest.mark.parametrize('strategy', ['semantic-legacy', 'semantic-ports', 'semantic-round',
                                     'semantic-width', 'semantic-depth', 'semantic-crossings',
                                     'semantic-auto', 'direct-bus'])
def test_unused_leading_declaration_does_not_shadow_live_output_lane(strategy):
    c = Cipher('anonymous_unused_first', 'permutation', ['unused', 'a', 'b'], [4]*3, 12)
    c.add_round()
    x = c.add_xor_component(['a', 'b'], [list(range(4))]*2, 4)
    c.add_cipher_output_component(['a', x.id, 'b'], [list(range(4))]*3, 12)
    ir = from_cipher(c)
    recovered = decode(encode(ir, strategy=strategy, annotations=True))
    assert recovered == ir
    compiled = to_cipher(recovered)
    for a in range(16):
        for b in range(16):
            assert compiled.evaluate([9, a, b]) == (a << 8) | ((a ^ b) << 4) | b


def test_final_output_metadata_cannot_reorder_unchanged_visible_body():
    text = encode(toy(), annotations=True)
    body, footer = framing(text)
    finals = [record for record in footer['records']
              if record['definition'].get('type') == 'cipher_output']
    assert len(finals) == 2
    left, right = sorted(finals, key=lambda record: record['col'])
    left['definition']['positions'], right['definition']['positions'] = (
        right['definition']['positions'], left['definition']['positions'])
    with pytest.raises(ValueError, match='visible left-to-right order'):
        decode(altered(body, footer))


@pytest.mark.parametrize('width', [24, 28, 32, 52])
def test_two_line_constant_visible_value_is_complete(width):
    import re
    value = (1 << width)-1
    ir = literal_ir(hex(value), width)
    for style in ('symbols', 'labels'):
        text = encode(ir, annotations=True, operator_style=style)
        body, footer = framing(text)
        # Read both interior text lines directly, without the native formatter.
        rows = body.splitlines()
        tokens = []
        for index in range(0, len(rows), 5):
            first, second = rows[index+1][2:9].strip(), rows[index+2][2:9].strip()
            token = first+second if first.startswith('x') else second
            if re.fullmatch(r'x[0-9A-F]+', token):
                tokens.append(token)
        assert tokens == ['x'+format(value, 'X')]
        assert to_cipher(decode(text)).evaluate([]) == value
        if width > 24:
            changed = body.replace('xFFFFFF', 'xEFFFFF', 1)
            assert changed != body
            with pytest.raises(ValueError, match='visible glyph'):
                decode(altered(changed, footer))


@pytest.mark.parametrize('width', [56, 64])
def test_constant_beyond_two_line_capacity_rejects_without_truncation(width):
    with pytest.raises(ValueError, match='visible manual label capacity'):
        encode(literal_ir(hex((1 << width)-1), width))



def test_dead_sink_is_visible_and_cannot_become_final_by_footer_reassignment():
    c = Cipher('anonymous_dead', 'permutation', ['a','b'], [4,4], 4)
    c.add_round()
    c.add_not_component(['a'], [list(range(4))], 4)
    c.add_cipher_output_component(['b'], [list(range(4))], 4)
    ir=from_cipher(c)
    text=encode(ir, annotations=True)
    body,footer=framing(text)
    assert 'DEAD' in body and 'OUT' in body
    assert decode(text)==ir
    assert to_cipher(decode(text)).evaluate([3,5])==5
    dead=next(r for r in footer['records'] if r['definition']['kind']=='discard')
    final=next(r for r in footer['records'] if r['definition'].get('type')=='cipher_output')
    wrong_width=copy.deepcopy(footer)
    next(r['definition'] for r in wrong_width['records'] if r['definition']['kind']=='discard')['bits']=8
    with pytest.raises(ValueError,match='Discard width'):
        decode(altered(body,wrong_width))
    footer['records'].remove(dead)
    final['row'],final['col']=dead['row'],dead['col']
    with pytest.raises(ValueError, match='Sink identity|Final anchor'):
        decode(altered(body,footer))


def test_input_fragment_order_is_visible_but_identifiers_can_be_renamed():
    c=Cipher('anonymous_identity','permutation',['a'],[8],8);c.add_round()
    c.add_cipher_output_component(['a'],[list(range(8))],8)
    ir=from_cipher(c);text=encode(ir,annotations=True,word_bits=4)
    body,footer=framing(text)
    assert to_cipher(decode(text)).evaluate([0x35])==0x35
    inputs=sorted((r['definition'] for r in footer['records'] if r['definition']['kind']=='input'),key=lambda d:d['index'])
    assert len(inputs)==2
    inputs[0]['positions'],inputs[1]['positions']=inputs[1]['positions'],inputs[0]['positions']
    with pytest.raises(ValueError,match='visible word index order'):
        decode(altered(body,footer))
    _,renamed=framing(text)
    for record in renamed['records']:
        if record['definition']['kind']=='input':record['definition']['id']='renamed'
    assert to_cipher(decode(altered(body,renamed))).evaluate([0x35])==0x35



@pytest.mark.parametrize('operation', ['xor', 'and', 'or'])
@pytest.mark.parametrize('repeated', [False, True])
def test_generic_three_port_gates_preserve_ordered_visible_operands(operation,repeated):
    c=Cipher('anonymous_three_ports','permutation',['a','b','c'],[4]*3,4);c.add_round()
    sources=['a','b','a' if repeated else 'c']
    x=getattr(c,'add_'+operation+'_component')(sources,[list(range(4))]*3,4)
    c.add_cipher_output_component([x.id],[list(range(4))],4)
    ir=from_cipher(c);text=encode(ir,annotations=True);restored=decode(text)
    assert restored==ir
    _,footer=framing(text)
    gate=next(r['definition'] for r in footer['records'] if r['definition'].get('type')=='word_operation')
    assert gate['operand_ports']==['left','top','right']
    compiled=to_cipher(restored)
    for a in range(16):
        for b in range(16):
            z=a if repeated else 9
            expected=a^b^z if operation=='xor' else a&b&z if operation=='and' else a|b|z
            assert compiled.evaluate([a,b,9])==expected



def test_three_port_repeated_rounds_and_renaming_keep_visible_semantics():
    c=Cipher('anonymous_rounds','permutation',['a','b','c'],[4]*3,12)
    sources=['a','b','c']
    for _ in range(3):
        c.add_round()
        x=c.add_xor_component(sources,[list(range(4))]*3,4)
        state=c.add_intermediate_output_component([x.id,sources[1],sources[2]],[list(range(4))]*3,12,'state')
        sources=[state.id]*3
        selections=[list(range(4)),list(range(4,8)),list(range(8,12))]
        if _!=2:
            # The next XOR has three fragments of the same declared state.
            x=c.add_xor_component(sources,selections,4)
            sources=[x.id,'b','c']
    c.add_cipher_output_component([x.id,'b','c'],[list(range(4))]*3,12)
    ir=from_cipher(c);text=encode(ir,annotations=True);assert decode(text)==ir
    renamed=copy.deepcopy(ir);mapping={item['id']:'input'+str(i) for i,item in enumerate(renamed['inputs'])}
    mapping.update({node['id']:'node'+str(i) for i,node in enumerate(renamed['nodes'])})
    for item in renamed['inputs']:item['id']=mapping[item['id']]
    for node in renamed['nodes']:
        node['id']=mapping[node['id']]
        for edge in node['operands']:edge['source']=mapping[edge['source']]
    assert encode(renamed)==framing(text)[0]
