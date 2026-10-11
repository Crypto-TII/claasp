import copy
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import (from_cipher,to_ascii,from_ascii,to_cipher,to_tikz,
    validate,state_snapshots,state_ascii,state_tikz,evaluate_state_values)


def circuit():
    c=Cipher('generic_probe','permutation',['data','control'],[8,4],4)
    c.add_round()
    x=c.add_xor_component(['data','control'],[[0,2,5,7],[3,2,1,0]],4)
    c.add_intermediate_output_component([x.id],[[0,1,2,3]],4,'state')
    c.add_cipher_output_component([x.id],[[0,1,2,3]],4)
    return c


def test_actual_glyph_roundtrip():
    source=circuit();ir=from_cipher(source,roles={'data':'data','control':'key'})
    text=to_ascii(ir)
    assert '# CLAASP-TYPED-GLYPH 1' in text and '+ CLAASP-DIAGRAMS 1 +' not in text
    assert from_ascii(text)==ir
    assert to_cipher(from_ascii(text)).evaluate([0xa5,7],intermediate_output=True)==source.evaluate([0xa5,7],intermediate_output=True)
    assert '\\begin{tikzpicture}' in to_tikz(ir,columnSpacing=2,wireStyle='smooth')


def test_unsupported_contract_fails_before_export():
    ir=from_cipher(circuit());ir['nodes'][0]['description']=['UNKNOWN_OPERATION',2]
    with pytest.raises(ValueError,match='unsupported native'):validate(ir)
    with pytest.raises(ValueError,match='unsupported native'):to_ascii(ir)
    with pytest.raises(ValueError,match='unsupported native'):to_cipher(ir)


def test_generic_states_and_differences():
    c=circuit();ir=from_cipher(c);v=evaluate_state_values(c,[0xa5,7]);other=evaluate_state_values(c,[0xa4,7])
    for mode in ['declared','round','layer']:
        frames=state_snapshots(ir,mode=mode,columns=4,values=v,comparison=other)
        assert frames and any(w['active'] for f in frames for w in f['words'])
        assert 'explicit-columns' in state_ascii(ir,mode=mode,columns=4,values=v)
        assert 'orange!25' in state_tikz(ir,mode=mode,columns=4,values=v,comparison=other)
    assert state_snapshots(ir)[0]['geometry']=='ambiguous-flat-fallback'
    with pytest.raises(ValueError):state_snapshots(ir,columns=0)
    with pytest.raises(ValueError):state_snapshots(ir,word_bits=3)


def test_renaming_invariant_geometry():
    ir=from_cipher(circuit());renamed=copy.deepcopy(ir);mapping={n['id']:f'identifier_{i}' for i,n in enumerate(renamed['inputs']+renamed['nodes'])}
    for n in renamed['inputs']+renamed['nodes']:n['id']=mapping[n['id']]
    for n in renamed['nodes']:
        for edge in n['operands']:edge['source']=mapping[edge['source']]
    renamed['name']='unseen_name'
    assert to_ascii(ir).split('# CLAASP-TYPED-GLYPH 1')[0]==to_ascii(renamed).split('# CLAASP-TYPED-GLYPH 1')[0]


def test_renamed_state_values_use_source_identities():
    c=circuit(); ir=from_cipher(c); renamed=copy.deepcopy(ir)
    mapping={n['id']:f'renamed_{i}' for i,n in enumerate(renamed['inputs']+renamed['nodes'])}
    for n in renamed['inputs']+renamed['nodes']:n['id']=mapping[n['id']]
    for n in renamed['nodes']:
        for edge in n['operands']:edge['source']=mapping[edge['source']]
    values=evaluate_state_values(to_cipher(renamed),[0xa5,7])
    expected=evaluate_state_values(c,[0xa5,7])
    for source,renamed_id in mapping.items():assert values[renamed_id]==expected[source]
    for mode in ['layer','round']:
        assert all(w['value'] is not None for f in state_snapshots(renamed,mode=mode,word_bits=4,values=values) for w in f['words'])


def test_boolean_not_parameter_is_rejected():
    c=Cipher('probe','permutation',['data'],[4],4);c.add_round()
    n=c.add_not_component(['data'],[[0,1,2,3]],4)
    c.add_cipher_output_component([n.id],[[0,1,2,3]],4)
    ir=from_cipher(c);ir['nodes'][0]['description'][1]=False
    with pytest.raises(ValueError,match='unsupported native'):validate(ir)


def test_integer_mix_column_zero_polynomial():
    c=Cipher('probe','permutation',['data'],[8],8);c.add_round()
    n=c.add_mix_column_component(['data'],[list(range(8))],8,[[[1,-1],[2,1]],0,4])
    c.add_cipher_output_component([n.id],[list(range(8))],8)
    ir=from_cipher(c);validate(ir);recovered=to_cipher(from_ascii(to_ascii(ir)))
    for value in range(256):
        a,b=value>>4,value&15
        expected=(((a-b)&15)<<4)|((2*a+b)&15)
        assert recovered.evaluate([value])==expected


def test_bounded_paginated_diagrams():
    ir=from_cipher(circuit())
    text=to_tikz(ir, rowsPerPanel=4, columnsPerPanel=2)
    assert text.count(r'\begin{tikzpicture}')>1
    assert r'\clearpage' in text
    with pytest.raises(ValueError, match='panels'):
        to_tikz(ir, rowsPerPanel=1, columnsPerPanel=1, maxPanels=1)
    frames=state_snapshots(ir, mode='declared', word_bits=4)
    state=state_tikz(ir, mode='declared', word_bits=4, columns_per_panel=1)
    assert state.count(r'\begin{tikzpicture}') == sum(len(f['words']) for f in frames)
    assert 'indices retained' in state
    with pytest.raises(ValueError, match='panels'):
        state_tikz(ir, mode='declared', word_bits=4, columns_per_panel=1, max_panels=1)
    with pytest.raises(ValueError, match='frame range'):
        state_tikz(ir, frame_range=[0,999])


def test_precise_legends_for_large_labels_and_values():
    c=Cipher('long_probe','permutation',['identifier_without_breaks_'*8],[128],128);c.add_round()
    source=c.inputs[0];c.add_cipher_output_component([source],[list(range(128))],128)
    ir=from_cipher(c);text=to_tikz(ir, rowsPerPanel=8, columnsPerPanel=3)
    assert r'\textbf{D0:0}' in text and r'\allowbreak{}' in text
    values=evaluate_state_values(c,[(1<<128)-1])
    state=state_tikz(ir,word_bits=128,values=values)
    assert r'\textbf{V0}' in state and 'V0' in state
    assert 'ffff' in state and r'\allowbreak{}' in state
