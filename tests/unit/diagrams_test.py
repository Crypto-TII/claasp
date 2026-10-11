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
