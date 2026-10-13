import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, to_cipher, from_ascii
from claasp.cipher_modules.diagram.manual_blocks import encode, decode, MARKER


def test_mixed_observation_fragment_flow_is_local_and_terminal_alias_rejects():
    c = Cipher('anonymous_mixed_flow', 'permutation', ['a', 'b'], [8, 8], 4)
    c.add_round()
    x = c.add_xor_component(['a', 'b'], [list(range(8))]*2, 8)
    observed = c.add_intermediate_output_component([x.id], [list(range(8))], 8, 'trace')
    c.add_cipher_output_component([observed.id], [list(range(4))], 4)
    ir = from_cipher(c, roles={'b': 'key'})
    text = encode(ir, annotations=True, word_bits=4)
    assert decode(text) == ir
    body, footer = text.split(MARKER)
    metadata = json.loads(footer)
    fragments = [record['definition'] for record in metadata['records'] if record['definition'].get('type') == 'intermediate_output']
    assert {record['flow'] for record in fragments} == {'alias', 'observe'}
    terminal = next(record for record in fragments if record['flow'] == 'observe')
    terminal['flow'] = 'alias'
    malformed_text = body+MARKER+json.dumps(metadata)
    with pytest.raises(ValueError, match='through-tap'):
        decode(malformed_text)
    restored = to_cipher(decode(text))
    for a in range(256):
        for b in [0, 255, 90]:
            assert restored.evaluate([a, b]) == (a^b)>>4
            assert restored.evaluate([a, b], intermediate_output=True)[1]['trace'][0] == a^b


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
    assert MARKER not in body
    assert '^' in body
    assert 'S  I2' in body
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
        malformed_text = altered(changed, footer)
        with pytest.raises(ValueError):
            decode(malformed_text)


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
    malformed_text = altered(body, footer)
    with pytest.raises(ValueError, match='every bit'):
        decode(malformed_text)


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
    malformed_text = altered(body, footer)
    with pytest.raises(ValueError, match='Noncommutative'):
        decode(malformed_text)


@pytest.mark.parametrize('field', ['source', 'operands', 'nodes', 'output_values', 'original_graph'])
def test_hidden_dependency_annotations_are_rejected(field):
    body, footer = framing(encode(toy(), annotations=True))
    footer['records'][0]['definition'][field] = []
    malformed_text = altered(body, footer)
    with pytest.raises(ValueError, match='Hidden dependency'):
        decode(malformed_text)


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
    candidate_ir = toy()
    with pytest.raises(ValueError):
        encode(candidate_ir, **options)


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
    malformed_text = altered(body.replace('KEY2', 'KEY1', 1), footer)
    with pytest.raises(ValueError, match='legend/stage'):
        decode(malformed_text)


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
        assert len(tokens) == 1
        assert int(tokens[0], 16) == expected
        assert 'xB101' not in body
        assert 'xB10001' not in body
        recovered = decode(to_ascii(ir, operator_style=style, annotations=True))
        assert recovered['nodes'][0]['description'] == [literal]
        assert to_cipher(recovered).evaluate([]) == expected


@pytest.mark.parametrize('literal,width', [
    ('0b102', 8), ('0b', 8), ('0x', 8), ('0xGG', 8), ('17', 8),
    ('-0x1', 8), ('0b10000', 4), ('0x100', 8),
])
def test_invalid_and_overwide_literals_fail_before_rendering(literal, width):
    from claasp.diagrams import to_ascii
    candidate_ir = literal_ir(literal, width)
    with pytest.raises(ValueError, match='unsupported native constant'):
        to_ascii(candidate_ir)


def test_visible_binary_literal_mutation_cannot_hide_behind_metadata():
    text = encode(literal_ir('0b101',8), annotations=True)
    body, footer = framing(text)
    assert 'x5' in body
    malformed_text = altered(body.replace('x5', 'x6', 1), footer)
    with pytest.raises(ValueError, match='definition disagrees with visible glyph'):
        decode(malformed_text)


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
    malformed_text = altered(body, footer)
    with pytest.raises(ValueError, match='visible left-to-right order'):
        decode(malformed_text)


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
            malformed_text = altered(changed, footer)
            with pytest.raises(ValueError, match='visible glyph'):
                decode(malformed_text)


@pytest.mark.parametrize('width', [56, 64])
def test_constant_beyond_two_line_capacity_rejects_without_truncation(width):
    candidate_ir = literal_ir(hex((1 << width)-1), width)
    with pytest.raises(ValueError, match='visible manual label capacity'):
        encode(candidate_ir)



def test_dead_sink_is_visible_and_cannot_become_final_by_footer_reassignment():
    c = Cipher('anonymous_dead', 'permutation', ['a','b'], [4,4], 4)
    c.add_round()
    c.add_not_component(['a'], [list(range(4))], 4)
    c.add_cipher_output_component(['b'], [list(range(4))], 4)
    ir=from_cipher(c)
    text=encode(ir, annotations=True)
    body,footer=framing(text)
    assert 'DEAD' in body
    assert 'OUT' in body
    assert decode(text)==ir
    assert to_cipher(decode(text)).evaluate([3,5])==5
    dead=next(r for r in footer['records'] if r['definition']['kind']=='discard')
    final=next(r for r in footer['records'] if r['definition'].get('type')=='cipher_output')
    wrong_width=copy.deepcopy(footer)
    next(r['definition'] for r in wrong_width['records'] if r['definition']['kind']=='discard')['bits']=8
    malformed_text = altered(body,wrong_width)
    with pytest.raises(ValueError,match='Discard width'):
        decode(malformed_text)
    footer['records'].remove(dead)
    final['row'],final['col']=dead['row'],dead['col']
    malformed_text = altered(body,footer)
    with pytest.raises(ValueError, match='Sink identity|Final anchor'):
        decode(malformed_text)


def test_input_fragment_order_is_visible_but_identifiers_can_be_renamed():
    c=Cipher('anonymous_identity','permutation',['a'],[8],8);c.add_round()
    c.add_cipher_output_component(['a'],[list(range(8))],8)
    ir=from_cipher(c);text=encode(ir,annotations=True,word_bits=4)
    body,footer=framing(text)
    assert to_cipher(decode(text)).evaluate([0x35])==0x35
    inputs=sorted((r['definition'] for r in footer['records'] if r['definition']['kind']=='input'),key=lambda d:d['index'])
    assert len(inputs)==2
    inputs[0]['positions'],inputs[1]['positions']=inputs[1]['positions'],inputs[0]['positions']
    malformed_text = altered(body,footer)
    with pytest.raises(ValueError,match='visible word index order'):
        decode(malformed_text)
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



@pytest.mark.parametrize('strategy',['semantic-auto','semantic-crossings'])
def test_observation_fragments_do_not_block_their_through_wires(strategy):
    c=Cipher('anonymous_observe','permutation',['a'],[16],16);c.add_round()
    positions=list(range(12,16))+list(range(12))
    x=c.add_rotate_component(['a'],[positions],16,1)
    c.add_intermediate_output_component(['a',x.id],[list(range(16))]*2,32,'state')
    c.add_cipher_output_component([x.id],[list(range(16))],16)
    ir=from_cipher(c);text=encode(ir,annotations=True,word_bits=4,strategy=strategy)
    assert decode(text)==ir
    compiled=to_cipher(decode(text))
    for value in [0,1,0x35,0x1234,0xffff]:
        permuted=((value&15)<<12)|(value>>4)
        expected=(permuted>>1)|((permuted&1)<<15)
        assert compiled.evaluate([value])==expected



def test_mixed_width_sbox_linear_and_field_matrix_have_direct_oracle():
    c=Cipher('anonymous_mixed','permutation',['a','b'],[8,8],12);c.add_round()
    r=c.add_rotate_component(['a'],[list(range(8))],8,3)
    x=c.add_xor_component([r.id,'b'],[list(range(8))]*2,8)
    table=[i^9 for i in range(16)]
    sub=c.add_sbox_component([x.id],[list(range(4,8))],4,table)
    mix=c.add_mix_column_component([x.id],[list(range(8))],8,[[[1,2],[3,1]],0x13,4])
    reverse=[[int(row+col==7) for col in range(8)] for row in range(8)]
    linear=c.add_linear_layer_component([mix.id],[list(range(8))],8,reverse)
    c.add_cipher_output_component([sub.id,linear.id],[list(range(4)),list(range(8))],12)
    ir=from_cipher(c);text=encode(ir,annotations=True);assert decode(text)==ir
    body,footer=framing(text)
    assert 'JOIN' in body
    assert 'SEL' in body
    assert 'MC' in body
    compiled=to_cipher(decode(text))
    def multiply(a,b):
        value=0
        for _ in range(4):
            if b&1:value^=a
            a<<=1
            if a&16:a^=0x13
            b>>=1
        return value&15
    for a in range(256):
        for b in (0,0x35,255):
            value=((a>>3)|((a&7)<<5))^b
            high,low=value>>4,value&15
            mixed=((high^multiply(2,low))<<4)|(multiply(3,high)^low)
            reversed_bits=int(format(mixed,'08b')[::-1],2)
            expected=((low^9)<<8)|reversed_bits
            assert compiled.evaluate([a,b])==expected
    changed=body.replace('|   S   |','|   L   |',1)
    assert changed!=body
    malformed_text = altered(changed,footer)
    with pytest.raises(ValueError,match='visible glyph'):
        decode(malformed_text)



def test_generic_layers_align_parallel_substitutions_and_preserve_word_lanes():
    c=Cipher('anonymous_layers','block_cipher',['state','key'],[16,16],16)
    words=[('state',list(range(i*4,(i+1)*4))) for i in range(4)]
    table=[(value*value+value+3)&15 for value in range(16)]
    for _ in range(2):
        c.add_round();updated=[]
        for i,(source,positions) in enumerate(words):
            x=c.add_xor_component([source,'key'],[positions,list(range(i*4,(i+1)*4))],4)
            sub=c.add_sbox_component([x.id],[list(range(4))],4,table)
            updated.append(sub.id)
        state=c.add_intermediate_output_component(updated,[list(range(4))]*4,16,'state')
        words=[(state.id,list(range(i*4,(i+1)*4))) for i in range(4)]
    c.add_cipher_output_component([source for source,_ in words],[positions for _,positions in words],16)
    ir=from_cipher(c,roles={'state':'data','key':'key'})
    text=encode(ir,annotations=True,strategy='semantic-layer');assert decode(text)==ir
    _,footer=framing(text)
    for round_index in range(2):
        substitutions=[r for r in footer['records'] if r['definition'].get('type')=='sbox' and r['definition']['round']==round_index]
        assert len(substitutions) == 4
        assert len({r['row'] for r in substitutions}) == 1
        assert sorted(r['col'] for r in substitutions)==[0,1,2,3]
    renamed=copy.deepcopy(ir)
    mapping={item['id']:'input'+str(index) for index,item in enumerate(renamed['inputs'])}
    mapping.update({node['id']:'node'+str(index) for index,node in enumerate(renamed['nodes'])})
    for item in renamed['inputs']:item['id']=mapping[item['id']]
    for node in renamed['nodes']:
        node['id']=mapping[node['id']]
        for edge in node['operands']:edge['source']=mapping[edge['source']]
    assert encode(renamed,strategy='semantic-layer')==framing(text)[0]
    compiled=to_cipher(decode(text))
    for state in range(256):
        for key in (0,0x1234,0xffff):
            expected=0
            for shift in (12,8,4,0):
                value=(state>>shift)&15;word_key=(key>>shift)&15
                value=table[value^word_key];value=table[value^word_key]
                expected=(expected<<4)|value
            assert compiled.evaluate([state,key])==expected



@pytest.mark.parametrize('strategy',['semantic-legacy','semantic-ports','semantic-round',
                                     'semantic-width','semantic-depth','semantic-crossings','semantic-auto'])
def test_deferred_constant_does_not_cross_a_reused_round_lane(strategy):
    c=Cipher('anonymous_late_constant','permutation',['a','b'],[4,4],4);c.add_round()
    first=c.add_constant_component(4,1);late=c.add_constant_component(4,2)
    y=c.add_xor_component(['a',first.id],[list(range(4))]*2,4)
    c.add_intermediate_output_component([y.id],[list(range(4))],4,'state')
    c.add_round();z=c.add_modsub_component(['b',y.id],[list(range(4))]*2,4)
    c.add_round();w=c.add_xor_component([z.id,late.id],[list(range(4))]*2,4)
    c.add_cipher_output_component([w.id],[list(range(4))],4)
    ir=from_cipher(c);text=encode(ir,annotations=True,strategy=strategy);assert decode(text)==ir
    restored=to_cipher(decode(text))
    for a in range(16):
        for b in range(16):assert restored.evaluate([a,b])==((b-(a^1))&15)^2



def test_balanced_gathering_shares_ordered_subtrees_without_changing_values():
    c=Cipher('anonymous_gather','permutation',['a','b'],[32,32],52);c.add_round()
    whole=c.add_xor_component(['a','b'],[list(range(32))]*2,32)
    prefix=c.add_and_component(['a','b'],[list(range(16))]*2,16)
    small=c.add_sbox_component(['a'],[list(range(28,32))],4,[value^9 for value in range(16)])
    c.add_cipher_output_component([whole.id,prefix.id,small.id],[list(range(32)),list(range(16)),list(range(4))],52)
    ir=from_cipher(c);text=encode(ir,annotations=True,gathering="balanced");assert decode(text)==ir
    _,footer=framing(text)
    # Each full eight-fragment input needs seven JOINs; its four-fragment
    # prefix reuses that existing subtree instead of adding three more.
    assert sum(r['definition']['kind']=='join' for r in footer['records'])==14
    compiled=to_cipher(decode(text))
    for a in (0,1,0x12345678,0xffffffff):
        for b in (0,0xabcdef01,0xffffffff):
            expected=((a^b)<<20)|(((a>>16)&(b>>16))<<4)|((a&15)^9)
            assert compiled.evaluate([a,b])==expected



def test_explicit_data_bank_keeps_outputs_below_data_instead_of_key_inputs():
    c=Cipher('anonymous_banks','block_cipher',['k','d'],[8,8],8);c.add_round()
    x=c.add_xor_component(['k','d'],[list(range(8))]*2,8)
    pieces=[c.add_sbox_component([x.id],[list(range(start,start+4))],4,[value^9 for value in range(16)]) for start in (0,4)]
    c.add_cipher_output_component([piece.id for piece in pieces],[list(range(4))]*2,8)
    ir=from_cipher(c,roles={'k':'key','d':'data'})
    text=encode(ir,annotations=True,lane_policy='state');assert decode(text)==ir
    _,footer=framing(text)
    outputs=[r for r in footer['records'] if r['definition'].get('type')=='cipher_output']
    assert sorted(r['col'] for r in outputs)==[2,3]
    compiled=to_cipher(decode(text))
    for key in range(256):
        for data in (0,0x35,255):assert compiled.evaluate([key,data])==(key^data^0x99)



def test_wordwise_projection_traces_fragment_gates_without_hidden_inputs():
    c=Cipher('anonymous_fragments','block_cipher',['k','d'],[8,8],8);c.add_round()
    x=c.add_xor_component(['k','d'],[list(range(8))]*2,8)
    pieces=[c.add_sbox_component([x.id],[list(range(start,start+4))],4,[value^9 for value in range(16)]) for start in (0,4)]
    c.add_cipher_output_component([piece.id for piece in pieces],[list(range(4))]*2,8)
    ir=from_cipher(c,roles={'k':'key','d':'data'})
    text=encode(ir,annotations=True,projection='wordwise',lane_policy='state');assert decode(text)==ir
    body,footer=framing(text)
    assert 'JOIN' not in body
    assert 'SEL' not in body
    fragments=[r for r in footer['records'] if r['definition']['kind']=='native_fragment']
    assert len(fragments)==2
    assert all(not any(key in r['definition'] for key in ('source','operands','nodes')) for r in fragments)
    compiled=to_cipher(decode(text))
    for key in range(256):
        for data in (0,0x35,255):assert compiled.evaluate([key,data])==(key^data^0x99)
    fragments[0]['definition']['positions'],fragments[1]['definition']['positions']=fragments[1]['definition']['positions'],fragments[0]['definition']['positions']
    # Unchanged scalar glyphs cannot introduce an invisible word permutation.
    malformed_text = altered(body,footer)
    with pytest.raises(ValueError,match='fragment|word|visible glyph'):
        decode(malformed_text)


@pytest.mark.parametrize('operation,arity', [('XOR',2),('AND',2),('OR',2),('NOT',1),('XOR',3),('AND',3),('OR',3)])
def test_generic_word_fragments_keep_ordered_selections_and_independent_values(operation,arity):
    c=Cipher('unseen_words','permutation',['a','b','c'][:arity],[8]*arity,8);c.add_round()
    masks=[list(reversed(range(8))),[4,5,6,7,0,1,2,3],list(range(8))][:arity]
    factory={'XOR':c.add_xor_component,'AND':c.add_and_component,'OR':c.add_or_component,'NOT':c.add_not_component}[operation]
    x=factory(c.inputs,masks,8)
    pieces=[c.add_sbox_component([x.id],[list(range(start,start+4))],4,[v^9 for v in range(16)]) for start in (0,4)]
    c.add_cipher_output_component([n.id for n in pieces],[list(range(4))]*2,8)
    ir=from_cipher(c,roles={});text=encode(ir,annotations=True,projection='wordwise')
    assert decode(text)==ir
    compiled=to_cipher(decode(text))
    def selected(value,mask):
        result=0
        for bit in mask:result=(result<<1)|((value>>(7-bit))&1)
        return result
    for seed in range(32):
        inputs=[(seed*37+index*83)&255 for index in range(arity)]
        values=[selected(value,mask) for value,mask in zip(inputs,masks)]
        result=(~values[0])&255 if operation=='NOT' else values[0]
        for value in values[1:]:
            if operation=='XOR':result^=value
            elif operation=='AND':result&=value
            elif operation=='OR':result|=value
        assert compiled.evaluate(inputs)==result^0x99
    for _ in range(3):
        assert encode(decode(text),annotations=True,projection='wordwise')==text
    renamed=copy.deepcopy(ir);mapping={item['id']:'v'+str(i) for i,item in enumerate(ir['inputs']+ir['nodes'])}
    renamed['name']='unseen_renamed'
    for item in renamed['inputs']+renamed['nodes']:item['id']=mapping[item['id']]
    for node in renamed['nodes']:
        for edge in node['operands']:edge['source']=mapping[edge['source']]
    assert encode(renamed,projection='wordwise')==framing(text)[0]


@pytest.mark.parametrize('mutation',['coverage','width','opcode','ordinal','hidden-source','glyph','anchor','negative-ordinal','empty-positions','boolean-position','oversized-anchor','missing-mask','ordinal-collision','port-reorder'])
def test_word_fragment_mutations_are_rejected(mutation):
    c=Cipher('unseen_mutations','permutation',['a','b'],[8,8],8);c.add_round()
    x=c.add_xor_component(c.inputs,[list(range(8))]*2,8)
    pieces=[c.add_sbox_component([x.id],[list(range(start,start+4))],4,list(range(16))) for start in (0,4)]
    c.add_cipher_output_component([n.id for n in pieces],[list(range(4))]*2,8)
    body,footer=framing(encode(from_cipher(c),annotations=True,projection='wordwise'))
    fragments=[r for r in footer['records'] if r['definition']['kind']=='native_fragment'];definition=fragments[0]['definition']
    if mutation=='coverage':definition['positions']=[0,1,2,2]
    elif mutation=='width':definition['bits']=12
    elif mutation=='opcode':definition['description'][0]='AND'
    elif mutation=='ordinal':definition['ordinal']+=1
    elif mutation=='hidden-source':definition['source']='a'
    elif mutation=='port-reorder':definition['operand_ports'].reverse()
    elif mutation=='negative-ordinal':definition['ordinal']=-1
    elif mutation=='empty-positions':definition['positions']=[]
    elif mutation=='boolean-position':definition['positions']=[False,1,2,3]
    elif mutation=='oversized-anchor':definition['ordinal']=36**7
    elif mutation=='missing-mask':
        for record in fragments:record['definition'].pop('operand_positions')
    elif mutation=='ordinal-collision':
        native=next(r['definition'] for r in footer['records'] if r['definition'].get('type')=='sbox')
        native['ordinal']=definition['ordinal']
    else:
        lines=body.splitlines();record=fragments[0];row=record['row']*5+(2 if mutation=='glyph' else 1);column=record['col']*11
        local=lines[row][column:column+11]
        local=local.replace('^','&') if mutation=='glyph' else local.replace('W0','W1')
        lines[row]=lines[row][:column]+local+lines[row][column+11:];body='\n'.join(lines)+'\n'
    malformed_text = altered(body,footer)
    with pytest.raises(ValueError):
        decode(malformed_text)


def test_public_opt_in_projection_controls_and_readable_vector_labels():
    from claasp.diagrams import to_ascii,synthesis_report,to_tikz
    c=Cipher('api_words','block_cipher',['k','d'],[8,8],8);c.add_round()
    x=c.add_xor_component(c.inputs,[list(range(8))]*2,8)
    pieces=[c.add_sbox_component([x.id],[list(range(s,s+4))],4,list(range(16))) for s in (0,4)]
    c.add_cipher_output_component([n.id for n in pieces],[list(range(4))]*2,8)
    ir=from_cipher(c,roles={'k':'key','d':'data'})
    text=to_ascii(ir,annotations=True,projection='wordwise',lane_policy='state');assert decode(text)==ir
    report=synthesis_report(ir,projection='wordwise',lane_policy='state')
    assert report['projection'] == 'wordwise'
    assert report['lane_policy'] == 'state'
    assert report['banks']=={'key':[0,2],'data':[2,4]}
    assert report['bank_reason'] == 'explicit-data-role'
    assert report['output_bank'] == 2
    vector=to_tikz(ir,layoutSource='human',projection='wordwise',lane_policy='state',view='wires')
    assert 'XOR/4' in vector
    assert 'word 0:1:3' in vector
    assert 'word 4:1:7' in vector
    assert '@21' not in vector
    assert 'DATA I1 bits 0:1:7' in vector
    assert 'KEY I0 bits 0:1:7' in vector
    from claasp.cipher_modules.diagram.glyphs import _numbered_ports
    cell={'ports':{'top':'in','left':'in','bottom':'out'},'reverse':True,'definition':{'operand_ports':['left','top']}}
    port_labels=_numbered_ports(1,2,cell)
    assert '(N1x2.west)' in port_labels[0]
    assert '{1}' in port_labels[0]
    assert '(N1x2.north)' in port_labels[1]
    assert '{2}' in port_labels[1]
    for kwargs in ({'projection':'cipher-template'},{'lane_policy':'name-based'},{'format':'audit','projection':'wordwise'},{'format':'audit','lane_policy':'state'}):
        with pytest.raises(ValueError):to_ascii(ir,**kwargs)


def test_noncontiguous_role_bank_reports_generic_fallback():
    from claasp.diagrams import synthesis_report
    c=Cipher('anonymous_interleaved','permutation',['x','k','y'],[4,4,4],8);c.add_round()
    c.add_cipher_output_component(['x','y'],[list(range(4))]*2,8)
    ir=from_cipher(c,roles={'x':'data','k':'key','y':'data'})
    report=synthesis_report(ir,lane_policy='state')
    assert 'data' not in report['banks']
    assert report['bank_reason'] == 'ambiguous-compact-fallback'
    assert report['output_bank'] == 0
    compiled=to_cipher(decode(encode(ir,lane_policy='state',annotations=True)))
    for a in range(16):
        for b in range(16):assert compiled.evaluate([a,9,b])==(a<<4)|b



def test_fragment_word_group_reference_is_unambiguous_and_operand_binding_is_visible():
    c=Cipher('opaque_group','block_cipher',['k','d'],[8,8],8);c.add_round()
    for _ in range(68):c.add_constant_component(4,0)
    x=c.add_xor_component(['d','k'],[list(range(8))]*2,8)
    pieces=[c.add_sbox_component([x.id],[list(range(s,s+4))],4,[v^9 for v in range(16)]) for s in (0,4)]
    c.add_cipher_output_component([n.id for n in pieces],[list(range(4))]*2,8)
    ir=from_cipher(c,roles={'k':'key','d':'data'})
    text=encode(ir,annotations=True,projection='wordwise',lane_policy='state')
    body,footer=framing(text)
    assert 'G1W.W0' in body
    assert 'G1W.W1' in body
    assert '^@21' in body
    assert decode(text)==ir
    compiled=to_cipher(decode(text))
    for key in (0,0x35,255):
        for data in (0,0xa5,255):assert compiled.evaluate([key,data])==(key^data^0x99)
    ambiguous=body.replace('G1W.W0',' G1WW0').replace('G1W.W1',' G1WW1')
    malformed_text = altered(ambiguous,footer)
    with pytest.raises(ValueError):
        decode(malformed_text)


@pytest.mark.parametrize('word_size',[1,4])
def test_generic_native_permutation_projects_ordered_wires_and_matches_independent_map(word_size):
    c=Cipher('anonymous_shuffle','permutation',['a','b'],[8,8],16);c.add_round()
    count=16//word_size;mapping=[(i+1)%count for i in range(count)]
    p=c.add_permutation_component(['a','b'],[list(reversed(range(8))),list(range(8))],16,mapping,word_size)
    c.add_cipher_output_component([p.id],[list(range(16))],16)
    ir=from_cipher(c,roles={});text=encode(ir,annotations=True,word_bits=4)
    assert decode(text)==ir
    compiled=to_cipher(decode(text))
    mask=(1<<word_size)-1
    for a in range(256):
        reversed_a=int(f'{a:08b}'[::-1],2)
        for b in (0,0x35,255):
            flat=(reversed_a<<8)|b;expected=0
            for source,destination in enumerate(mapping):
                word=(flat>>(16-(source+1)*word_size))&mask
                expected|=word<<(16-(destination+1)*word_size)
            assert compiled.evaluate([a,b])==expected
    renamed=copy.deepcopy(ir);ids={n['id']:'value'+str(i) for i,n in enumerate(ir['inputs']+ir['nodes'])}
    renamed['name']='unseen_family'
    for n in renamed['inputs']+renamed['nodes']:n['id']=ids[n['id']]
    for n in renamed['nodes']:
        for e in n['operands']:e['source']=ids[e['source']]
    assert encode(renamed,word_bits=4)==framing(text)[0]
    for _ in range(3):assert encode(decode(text),annotations=True,word_bits=4)==text
    body,footer=framing(text)
    d=next(r['definition'] for r in footer['records'] if r['definition'].get('type')=='permutation')
    d['description'][0][0]=d['description'][0][1]
    malformed_text = altered(body,footer)
    with pytest.raises(ValueError):
        decode(malformed_text)


@pytest.mark.parametrize('alignment',['left','right'])
def test_routing_cost_counts_strict_intervals_and_nearest_free_ties(alignment):
    from collections import Counter
    from claasp.cipher_modules.diagram.manual_blocks import _Scheduler
    scheduler=_Scheduler.__new__(_Scheduler)
    a,b=('input',0),('input',1)
    scheduler.calls=[{'args':[a,b]}];scheduler.slots={a:0,b:7}
    scheduler.active={0,3,7};scheduler.maximum=7;scheduler.alignment=alignment
    scheduler.uses=Counter({a:2,b:2})
    assert scheduler.routing_estimate(0)==(1,0)
    scheduler.uses[a]=1
    assert scheduler.routing_estimate(0)==(1,1)
    scheduler.calls=[{'args':[a,a]}];scheduler.uses[a]=2
    assert scheduler.routing_estimate(0)==(0,1)



@pytest.mark.parametrize('projection',['whole','wordwise'])
def test_explicit_word_width_keeps_partial_repeated_multi_source_selections(projection):
    c=Cipher('opaque_partial','permutation',['a','b'],[8,8],8);c.add_round()
    masks=[[7,0,2,7,5],[6,1,6],[4,0,4,2,7],[5,1,5]]
    n=c.add_xor_component(['a','b','b','a'],masks,8)
    c.add_cipher_output_component([n.id],[list(range(8))],8)
    ir=from_cipher(c,roles={});text=encode(ir,annotations=True,word_bits=4,projection=projection)
    assert decode(text)==ir
    restored=to_cipher(decode(text))
    def select(value,mask):
        result=0
        for bit in mask:result=(result<<1)|((value>>(7-bit))&1)
        return result
    for a in range(256):
        for b in (0,0x5a,255):
            left=(select(a,masks[0])<<3)|select(b,masks[1])
            right=(select(b,masks[2])<<3)|select(a,masks[3])
            assert restored.evaluate([a,b])==left^right
    for _ in range(3):assert encode(decode(text),annotations=True,word_bits=4,projection=projection)==text
    renamed=copy.deepcopy(ir);ids={n['id']:'opaque'+str(i) for i,n in enumerate(ir['inputs']+ir['nodes'])}
    for n in renamed['inputs']+renamed['nodes']:n['id']=ids[n['id']]
    for n in renamed['nodes']:
        for e in n['operands']:e['source']=ids[e['source']]
    assert encode(renamed,word_bits=4,projection=projection)==framing(text)[0]


def test_one_bit_edge_fragments_gather_into_word_sbox_without_lost_bits():
    c=Cipher('opaque_strided','permutation',['a','b'],[8,8],4);c.add_round()
    s=c.add_sbox_component(['a','a','b','b'],[[0],[5],[2],[7]],4,[value^9 for value in range(16)])
    c.add_cipher_output_component([s.id],[list(range(4))],4)
    ir=from_cipher(c,roles={});text=encode(ir,annotations=True,word_bits=4);assert decode(text)==ir
    restored=to_cipher(decode(text))
    for a in range(256):
        for b in (0,0x5a,255):
            selected=(((a>>7)&1)<<3)|(((a>>2)&1)<<2)|(((b>>5)&1)<<1)|(b&1)
            assert restored.evaluate([a,b])==selected^9
    body,footer=framing(text)
    helper=next(r['definition'] for r in footer['records'] if r['definition']['kind']=='selection')
    helper['positions']=[100]
    malformed_text = altered(body,footer)
    with pytest.raises(ValueError):
        decode(malformed_text)
