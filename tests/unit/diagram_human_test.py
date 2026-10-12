import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, to_ascii, to_audit_ascii, from_ascii, to_cipher, synthesis_report
from claasp.cipher_modules.diagram.manual_blocks import MARKER


def toy(left='left', right='right'):
    c = Cipher('generic_probe', 'permutation', [left, right], [4,4], 8)
    c.add_round()
    node = c.add_xor_component([left,right], [list(range(4))]*2, 4)
    c.add_cipher_output_component([node.id,right], [list(range(4))]*2, 8)
    return from_cipher(c)


def manifest(text):
    return json.loads(text.split(MARKER)[1])


def test_default_is_deterministic_manual_body_and_preserves_ir():
    ir = toy(); before = copy.deepcopy(ir)
    text = to_ascii(ir)
    assert text == to_ascii(ir) and ir == before
    assert MARKER not in text and '# CLAASP-TYPED' not in text
    assert len(text.splitlines()) % 5 == 0
    assert all(len(line) % 11 == 0 for line in text.splitlines())
    assert '^' in text and '___v___' in text


def test_identifier_renaming_preserves_entire_body_geometry():
    assert to_ascii(toy()) == to_ascii(toy('opaque_long_identifier','z'))


def test_real_render_options_preserve_annotated_native_semantics():
    ir = toy()
    text = to_ascii(ir, operator_style='labels', wire_borders=True, annotations=True)
    assert 'XOR' in text and from_ascii(text) == ir


def test_noncontiguous_selection_is_visible_and_reconstructs():
    ir = toy(); ir['nodes'][0]['operands'][0]['positions'] = [0,2,1,3]
    text = to_ascii(ir, annotations=True)
    assert 'SEL' in text and from_ascii(text) == ir


@pytest.mark.parametrize('kwargs', [{'alignment':'center'},{'word_bits':-1},{'word_bits':0},{'word_bits':False},{'annotations':1},{'wire_borders':1},{'layout_preference':'bad'}])
def test_invalid_supported_options_are_rejected(kwargs):
    with pytest.raises(ValueError):to_ascii(toy(), **kwargs)


def test_unsupported_spacing_is_not_an_advertised_knob():
    with pytest.raises(TypeError):to_ascii(toy(), column_spacing=18)


def test_public_human_and_audit_lossless_modes():
    ir = toy()
    assert from_ascii(to_ascii(ir,annotations=True)) == ir
    assert from_ascii(to_audit_ascii(ir)) == ir
    assert to_ascii(ir,format='audit') == to_audit_ascii(ir)
    with pytest.raises(ValueError):to_ascii(ir,format='audit',annotations=True)


def test_native_roles_and_explicit_override():
    from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    c = SpeckBlockCipher(number_of_rounds=1)
    assert [i['role'] for i in from_cipher(c)['inputs']] == ['data','key']
    assert all(i['role']=='unspecified' for i in from_cipher(c,roles={})['inputs'])
    arbitrary = Cipher('key_named','permutation',['key'],[4],4);arbitrary.add_round()
    arbitrary.add_cipher_output_component(['key'],[list(range(4))],4)
    assert from_cipher(arbitrary)['inputs'][0]['role']=='unspecified'


def test_permuted_and_repeated_outputs_share_declared_bottom_anchors():
    for ids in (['right','left'],['left','left']):
        c = Cipher('generic_order','permutation',['left','right'],[4,4],8);c.add_round()
        c.add_cipher_output_component(ids,[list(range(4))]*2,8)
        ir = from_cipher(c);text = to_ascii(ir,word_bits=4,annotations=True)
        boundaries = [r for r in manifest(text)['records'] if r['definition'].get('type')=='cipher_output']
        assert len({r['row'] for r in boundaries})==1
        assert all(r['col']==r['definition']['positions'][0]//4 for r in boundaries)
        assert from_ascii(text)==ir


def test_noncommutative_operands_keep_actual_visible_order():
    c = Cipher('generic_sub','permutation',['a','b'],[4,4],4);c.add_round()
    n = c.add_modsub_component(['b','a'],[list(range(4))]*2,4)
    c.add_cipher_output_component([n.id],[list(range(4))],4)
    ir=from_cipher(c);text=to_ascii(ir,annotations=True)
    assert from_ascii(text)==ir and to_cipher(from_ascii(text)).evaluate([3,7])==4


def test_speck_observations_unused_legend_and_expanded_key_rounds():
    from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    one = to_ascii(SpeckBlockCipher(number_of_rounds=1))
    five = to_ascii(SpeckBlockCipher(number_of_rounds=5))
    assert 'KEY6' in one and 'UNUSED' in one and 'I3-5' in one and 'OBS0' in one
    assert one.count('>>>7')==1 and one.count('<<<2')==1
    assert five.count('>>>7')==9 and five.count('<<<2')==9
    assert all('R'+str(r) in five for r in range(5))
    ir=from_cipher(SpeckBlockCipher(number_of_rounds=5))
    assert from_ascii(to_ascii(ir,annotations=True))==ir
    assert all(any(n['description']==['round_key_output'] and n['round']==r and n['operands'][0]['source']==f'xor_{r}_5' for n in ir['nodes']) for r in range(1,5))


def test_generic_feistel_f_chain_and_exchange_independent_oracle():
    c=Cipher('generic_feistel','permutation',['left','right'],[4,4],8);c.add_round()
    r=c.add_rotate_component(['right'],[list(range(4))],4,1)
    f=c.add_not_component([r.id],[list(range(4))],4)
    x=c.add_xor_component(['left',f.id],[list(range(4))]*2,4)
    c.add_cipher_output_component(['right',x.id],[list(range(4))]*2,8)
    text=to_ascii(c,annotations=True);rebuilt=to_cipher(from_ascii(text))
    assert '>>>1' in text and '!' in text and '^' in text and '<---------->' in text
    for left in range(16):
        for right in range(16):
            rotated=(right>>1)|((right&1)<<3)
            assert rebuilt.evaluate([left,right]) == (right<<4)|(left^(rotated^15))


@pytest.mark.parametrize('options',[{'max_calls':1},{'max_cells':1},{'max_grid_area':1},{'max_text_bytes':1},{'format':'bad'}])
def test_public_work_bounds_fail_explicitly(options):
    with pytest.raises(ValueError):to_ascii(toy(),**options)


def test_public_report_and_compatibility_exports():
    import claasp.diagrams as compatibility
    import claasp.cipher_modules.diagram as package
    assert compatibility.to_ascii is package.to_ascii
    assert compatibility.to_audit_ascii is package.to_audit_ascii
    report=synthesis_report(toy(),layout_preference='width')
    assert report['layout_preference']=='width' and len(report['candidates'])==6
    assert set(report['metrics'])=={'crossings','depth','width','cells'}



def test_manual_tikz_reuses_verified_cells_instead_of_audit_planner(monkeypatch):
    from claasp.diagrams import to_tikz
    from claasp.cipher_modules.diagram import glyphs, manual_blocks
    ir=toy();expected_cells,expected_report=manual_blocks.build(ir)
    def no_audit(*args,**kwargs):
        raise AssertionError('Human vector path must not invoke audit planner')
    monkeypatch.setattr(glyphs,'_encode_layout',no_audit)
    tikz=to_tikz(ir,layoutSource='human',view='wires',legend='none',columnsPerPanel=20,rowsPerPanel=20)
    assert 'Consolidated manual synthesis' in tikz
    assert 'OUT/4' in tikz and 'I0 input/4' in tikz
    for (row,col),cell in expected_cells.items():
        if cell['kind'] in ('input','box','output','tap','note'):
            assert '(N'+str(row)+'x'+str(col)+')' in tikz
    with pytest.raises(ValueError,match='layoutSource'):
        to_tikz(ir,layoutSource='by-name')


def test_manual_tikz_exchange_is_visible_as_two_crossed_routes():
    from claasp.diagrams import to_tikz
    c=Cipher('generic_exchange','permutation',['a','b'],[4,4],8);c.add_round()
    x=c.add_xor_component(['a','b'],[list(range(4))]*2,4)
    c.add_cipher_output_component(['b',x.id],[list(range(4))]*2,8)
    ir=from_cipher(c)
    text=to_ascii(ir,annotations=True)
    assert '<---------->' in text
    tikz=to_tikz(ir,layoutSource='human',view='wires',legend='none',rowsPerPanel=30,columnsPerPanel=10)
    assert tikz.count('to[out=-90,in=90]')==2



def test_state_auto_word_granularity_is_shared_but_shape_stays_ambiguous():
    from claasp.diagrams import state_snapshots
    from claasp.cipher_modules.diagram.manual_blocks import infer_word_bits
    ir=toy();frames=state_snapshots(ir,word_bits=None)
    assert infer_word_bits(ir)==4
    assert frames[0]['word_bits']==4 and len(frames[0]['words'])==2
    assert frames[0]['word_bits_source']=='inferred-gcd'
    assert frames[0]['geometry']=='ambiguous-flat-fallback'
    explicit=state_snapshots(ir,word_bits=None,columns=1)
    assert explicit[0]['geometry']=='explicit-columns' and explicit[0]['rows']==2



def test_human_vector_input_references_and_all_boundary_fragments_are_retained():
    from claasp.diagrams import to_tikz
    from claasp.cipher_modules.diagram.manual_blocks import _encode_layout
    from claasp.cipher_modules.diagram.presentation import _member_locations
    c=Cipher('anonymous_split','permutation',['a'],[8],8);c.add_round()
    c.add_intermediate_output_component(['a'],[list(range(8))],8,'state')
    c.add_cipher_output_component(['a'],[list(range(8))],8)
    ir=from_cipher(c);_,cells,_=_encode_layout(ir,word_bits=4)
    locations=_member_locations(cells)
    for node in ir['nodes']:
        parts=[(key,cell['definition']) for key,cell in cells.items() if cell.get('definition',{}).get('id')==node['id']]
        assert len(parts)==2
        for (row,col),definition in parts:
            assert f'D{row}:{col}[' in locations[node['id']][0]
    text=to_tikz(ir,layoutSource='human',word_bits=4,view='wires',columnsPerPanel=20,rowsPerPanel=20)
    assert 'I0: a' in text and text.count('I0 input/4')==2
    assert 'I1 input/4' not in text



def test_human_vector_partial_unused_note_uses_native_input_and_bit_range():
    from claasp.diagrams import to_tikz
    c=Cipher('anonymous_partial','permutation',['a'],[8],4);c.add_round()
    c.add_cipher_output_component(['a'],[[0,1,2,3]],4)
    ir=from_cipher(c)
    plain=to_ascii(ir,word_bits=4)
    assert '(  I2   )' in plain
    assert from_ascii(to_ascii(ir,word_bits=4,annotations=True))==ir
    vector=to_tikz(ir,layoutSource='human',word_bits=4,view='wires')
    assert 'I0 bits 4:1:7' in vector and '{I2}' not in vector
    assert 'I0 input/4' in vector and 'I0: a' in vector
