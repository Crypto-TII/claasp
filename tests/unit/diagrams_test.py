import copy
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import (from_cipher,to_ascii,from_ascii,to_cipher,to_tikz,
    validate,state_snapshots,state_ascii,state_tikz,evaluate_state_values)


def _box_contents(text, start):
    depth, index, output = 1, start, []
    while depth:
        char = text[index]
        if char == chr(92):
            output.extend(text[index:index+2])
            index += 2
            continue
        if char == '{':
            depth += 1
        if char == '}':
            depth -= 1
        if depth:
            output.append(char)
        index += 1
    return ''.join(output), index


def _table_text(text):
    output, index = [], 0
    while index < len(text):
        if text.startswith(r'\mbox{', index):
            content, index = _box_contents(text, index+6)
            output.append(content)
        else:
            output.append(text[index])
            index += 1
    return ''.join(output).replace(r'\newline{}', '').replace(r'\allowbreak{}', '')


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
    assert '# CLAASP-TYPED-GLYPH 1' in text
    assert '+ CLAASP-DIAGRAMS 1 +' not in text
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
        assert frames
        assert any((w['active'] for f in frames for w in f['words']))
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
    text=to_tikz(ir, view="wires", rowsPerPanel=4, columnsPerPanel=2)
    assert text.count(r'\begin{tikzpicture}')>1
    assert r'\clearpage' in text
    with pytest.raises(ValueError, match='panels'):
        to_tikz(ir, view="wires", rowsPerPanel=1, columnsPerPanel=1, maxPanels=1)
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
    ir=from_cipher(c);text=to_tikz(ir, view="wires", legend="audit", rowsPerPanel=8, columnsPerPanel=3)
    assert 'D0:0' in text
    assert 'Optional audit' in text
    assert '\\mbox{' in text
    values=evaluate_state_values(c,[(1<<128)-1])
    state=state_tikz(ir,word_bits=128,values=values)
    assert '\\textbf{V0}' in state
    assert 'V0' in state
    assert 'ffff' in state
    assert '\\allowbreak{}' in state


def test_native_role_annotations_survive_class_reimport():
    ir=from_cipher(circuit(),roles={'data':'data','control':'key'})
    rebuilt=to_cipher(ir)
    assert [i['role'] for i in from_cipher(rebuilt)['inputs']]==['data','key']
    assert [i['role'] for i in from_cipher(rebuilt,roles={})['inputs']]==['unspecified','unspecified']
    assert [i['role'] for i in from_cipher(rebuilt,roles={'control':'data'})['inputs']]==['unspecified','data']


def test_native_runtime_needs_no_external_process(monkeypatch):
    import subprocess
    def forbidden(*args,**kwargs): raise AssertionError('Diagram runtime created a subprocess')
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    ir=from_cipher(circuit(),roles={'control':'key'})
    assert from_ascii(to_ascii(ir))==ir
    assert r'\begin{tikzpicture}' in to_tikz(ir)


def test_compact_native_register_program_with_mixed_widths_and_constant_observers():
    """Native boxes must reach the shared planner and survive visible parsing."""
    c=Cipher('arbitrary_structure','permutation',['data','key'],[24,24],24)
    widths=[4,8,4,8]
    offsets=[0,4,12,16]
    state=[('data',list(range(offset,offset+width))) for offset,width in zip(offsets,widths)]
    for r in range(4):
        c.add_round()
        next_state=[]
        for i,((source,positions),width,offset) in enumerate(zip(state,widths,offsets)):
            constant=c.add_constant_component(width,(r+i)%2**width)
            # Independent constant-only observation cones previously broke
            # generic component ordering before the register fallback ran.
            c.add_intermediate_output_component([constant.id],[list(range(width))],width,'probe')
            rotate=c.add_rotate_component([source],[positions],width,-1-i)
            xor=c.add_xor_component([rotate.id,'key'],[list(range(width)),list(reversed(range(offset,offset+width)))],width)
            add=c.add_modadd_component([xor.id,constant.id],[list(range(width)),list(range(width))],width)
            next_state.append((add.id,list(range(width))))
        state=next_state
        c.add_intermediate_output_component([x[0] for x in state],[x[1] for x in state],24,'round_output')
    c.add_cipher_output_component([x[0] for x in state],[x[1] for x in state],24)
    ir=from_cipher(c,roles={'data':'data','key':'key'})
    from claasp.diagram_glyphs import build_grid
    grid,report=build_grid(ir)
    baseline,base=build_grid(ir,strategy='direct-bus')
    assert report['pattern']=='live-register-program'
    assert report['rows']*report['cols']+report['blocks']<base['rows']*base['cols']+base['blocks']
    parsed=from_ascii(to_ascii(ir))
    rebuilt=to_cipher(parsed)
    for inputs in [[0,0],[0xffffff,0],[0xa51234,0xfedcba]]:
        assert rebuilt.evaluate(inputs,intermediate_output=True)==c.evaluate(inputs,intermediate_output=True)


def test_generic_parallel_unary_geometry_and_visible_binding_mutation():
    from claasp.diagram_glyphs import build_grid, MARKER
    import json
    c=Cipher('unnamed_parallel','permutation',['a','b'],[4,4],8);c.add_round()
    a=c.add_rotate_component(['a'],[list(range(4))],4,-1)
    b=c.add_rotate_component(['b'],[list(range(4))],4,-1)
    c.add_cipher_output_component([b.id,a.id],[list(range(4)),list(range(4))],8)
    ir=from_cipher(c);grid,_=build_grid(ir)
    rotation_rows=[r for (r,col),cell in grid.items() if cell.get('definition',{}).get('description')==['ROTATE',-1]]
    assert len(rotation_rows) == 2
    assert rotation_rows[0] == rotation_rows[1]
    text=to_ascii(ir);assert '@21' in text
    changed=text.replace('@21','   ',1)
    assert from_ascii(changed)!=ir  # Visible binding, not metadata, changes operands.
    glyph,footer=text.split(MARKER);manifest=json.loads(footer)
    manifest['records'][0]['definition']['operands']=[]
    malformed = glyph+MARKER+json.dumps(manifest)
    with pytest.raises(ValueError,match='hidden dependency'):
        from_ascii(malformed)


def test_native_work_bounds_and_long_iterative_trace():
    ir=from_cipher(circuit())
    with pytest.raises(ValueError,match='max_calls'):to_ascii(ir,max_calls=1)
    with pytest.raises(ValueError,match='max_cells'):to_ascii(ir,max_cells=1)
    text=to_ascii(ir)
    with pytest.raises(ValueError,match='max_text_bytes'):from_ascii(text,max_text_bytes=16)
    with pytest.raises(ValueError,match='max_grid_area'):from_ascii(text,max_grid_area=1)
    # A deep one-lane DAG must not depend on Python's recursion limit.
    ir={'schema':'claasp-diagrams/1','name':'deep_unnamed','cipher_type':'permutation',
        'inputs':[{'id':'data','bits':8,'role':'data'}],'rounds':1,'output_bits':8,'nodes':[]}
    source='data'
    for i in range(2200):
        identity=f'n{i}'
        ir['nodes'].append({'id':identity,'type':'word_operation','bits':8,'input_bits':8,'round':0,
            'description':['ROTATE',-1],'operands':[{'source':source,'positions':list(range(8))}]})
        source=identity
    ir['nodes'].append({'id':'end','type':'cipher_output','bits':8,'input_bits':8,'round':0,
        'description':['cipher_output'],'operands':[{'source':source,'positions':list(range(8))}]})
    assert from_ascii(to_ascii(ir))==ir


@pytest.mark.parametrize('strategy',['semantic-auto','direct-bus'])
@pytest.mark.parametrize('operation',['xor','modsub'])
def test_ready_constants_make_progress_with_unused_input_and_tap(strategy,operation):
    c=Cipher('constant_graph','permutation',['unused'],[4],4);c.add_round()
    a=c.add_constant_component(4,9);b=c.add_constant_component(4,3)
    c.add_intermediate_output_component([a.id],[list(range(4))],4,'constant_probe')
    method=getattr(c,'add_'+operation+'_component')
    result=method([b.id,a.id],[list(range(4)),list(range(4))],4)
    c.add_cipher_output_component([result.id],[list(range(4))],4)
    ir=from_cipher(c);parsed=from_ascii(to_ascii(ir,strategy=strategy))
    assert parsed==ir
    assert to_cipher(parsed).evaluate([0],intermediate_output=True)==c.evaluate([0],intermediate_output=True)


def test_tikz_exposes_reversed_order_and_numbered_ports():
    c=Cipher('ordered','permutation',['a','b'],[4,4],4);c.add_round()
    sub=c.add_modsub_component(['b','a'],[list(range(4)),list(range(4))],4)
    c.add_cipher_output_component([sub.id],[list(range(4))],4)
    ir=from_cipher(c)
    assert '@21' in to_ascii(ir)
    vector=to_tikz(ir,view="wires")
    assert '@21' in vector
    assert '{1};' in vector
    assert '{2};' in vector
    ir2=from_cipher(circuit())
    assert '{1};' in to_tikz(ir2, view='wires')
    assert '{2};' in to_tikz(ir2, view='wires')


def test_record_import_and_rectangular_export_bounds_precede_render(monkeypatch):
    from claasp.diagrams import to_records
    import claasp.diagram_glyphs as glyphs
    ir=from_cipher(circuit());record=to_records(ir)
    with pytest.raises(ValueError,match='max_text_bytes'):from_ascii(record,max_text_bytes=1)
    with pytest.raises(ValueError,match='max_grid_area'):from_ascii(record,max_grid_area=1)
    def forbidden(*args,**kwargs):raise AssertionError('Rendered before checking output bounds')
    monkeypatch.setattr(glyphs,'render_grid',forbidden)
    with pytest.raises(ValueError,match='max_grid_area'):to_ascii(ir,max_grid_area=1)
    with pytest.raises(ValueError,match='max_text_bytes'):to_ascii(ir,max_text_bytes=1)


def test_generic_local_port_selections_preserve_visible_sources_and_fragments():
    import json
    from claasp.diagram_glyphs import MARKER
    c=Cipher('no_template','permutation',['wide','small'],[8,4],8);c.add_round()
    x=c.add_modsub_component(['wide','small'],[[7,0,7,1],[3,2,1,0]],4)
    c.add_intermediate_output_component([x.id],[list(range(4))],4,'tap')
    c.add_cipher_output_component([x.id,x.id],[[3,0,2,1],[0,1,2,3]],8)
    ir=from_cipher(c,roles={'small':'key'});text=to_ascii(ir,strategy='semantic-ports')
    assert from_ascii(text)==ir
    rebuilt=to_cipher(from_ascii(text))
    for d,k in [(0,0),(255,15),(0xa5,7)]:
        assert rebuilt.evaluate([d,k],intermediate_output=True)==c.evaluate([d,k],intermediate_output=True)
    manifest=json.loads(text.split(MARKER)[1]);definitions=[r['definition'] for r in manifest['records']]
    assert not any(d['kind']=='selection' for d in definitions)
    assert any('operand_positions' in d for d in definitions)
    assert all('operands' not in d for d in definitions)
    for d in definitions:
        if 'operand_positions' in d:d['operand_positions'][0][0]=10**9;break
    malformed = text.split(MARKER)[0]+MARKER+json.dumps(manifest)
    with pytest.raises(ValueError,match='local operand positions'):
        from_ascii(malformed)


def test_unobserved_constant_cone_both_layout_variants():
    for strategy in ['semantic-auto','semantic-ports','direct-bus']:
        c=Cipher('constant_only','permutation',['unused'],[4],4);c.add_round()
        a=c.add_constant_component(4,9);b=c.add_constant_component(4,3)
        x=c.add_modsub_component([b.id,a.id],[list(range(4)),list(range(4))],4)
        c.add_cipher_output_component([x.id],[list(range(4))],4)
        ir=from_cipher(c);assert from_ascii(to_ascii(ir,strategy=strategy))==ir


def test_parallel_layers_use_visible_local_masks_and_independent_arithmetic():
    import json
    from claasp.diagram_glyphs import MARKER
    c=Cipher('arbitrary_layers','permutation',['data'],[8],8);c.add_round()
    first=[c.add_rotate_component(['data'],[list(range(i,i+4))],4,-1) for i in (0,4)]
    second=[c.add_not_component([n.id],[list(range(4))],4) for n in first]
    c.add_cipher_output_component([n.id for n in reversed(second)],[list(range(4))]*2,8)
    ir=from_cipher(c);text=to_ascii(ir,strategy='semantic-parallel')
    glyph,footer=text.split(MARKER);manifest=json.loads(footer)
    groups=[r['definition'] for r in manifest['records'] if r['definition']['kind']=='parallel']
    assert len(groups) == 2
    assert all((len(g['members']) == 2 for g in groups))
    parsed=from_ascii(text);assert parsed==ir
    rebuilt=to_cipher(parsed)
    def rotate(x):return ((x<<1)|(x>>3))&15
    for x in range(256):
        expected=((rotate(x&15)^15)<<4)|(rotate(x>>4)^15)
        assert rebuilt.evaluate([x])==expected
    renamed=copy.deepcopy(ir)
    names={n['id']:'anonymous_'+str(i) for i,n in enumerate(ir['inputs']+ir['nodes'])}
    for n in renamed['inputs']+renamed['nodes']:
        n['id']=names[n['id']]
        for edge in n.get('operands',[]):edge['source']=names[edge['source']]
    assert from_ascii(to_ascii(renamed,strategy='semantic-parallel'))==renamed
    for mutation,match in [(lambda g:g['members'][0].update(operands=[]),'Hidden dependency'),
                           (lambda g:g['members'][0].update(bits=10**9),'member width|explicit bit expansion'),
                           (lambda g:g['members'][0]['operand_positions'][0].__setitem__(0,10**9),'local operand positions')]:
        broken=copy.deepcopy(manifest)
        group=next(r['definition'] for r in broken['records'] if r['definition']['kind']=='parallel')
        mutation(group)
        malformed = glyph+MARKER+json.dumps(broken)
        with pytest.raises(ValueError,match=match):from_ascii(malformed)
    # Removing visible binding must affect parsing despite an unchanged footer.
    changed=text.replace('@21','   ',1)
    if changed!=text:
        try:assert from_ascii(changed)!=ir
        except ValueError:pass


def test_aggregate_group_limits_precede_visible_stream_allocation():
    import json
    from claasp.diagram_glyphs import MARKER
    ir=from_cipher(circuit());drawing,footer=to_ascii(ir).split(MARKER)
    manifest=json.loads(footer)
    template={'id':'member','type':'word_operation','bits':1,'input_bits':1,'round':0,'description':['NOT'],'ordinal':0,'operand_positions':[[0]]}
    record={'row':0,'col':0,'definition':{'kind':'parallel','bits':10001,'tag':'group','members':[template]*10001}}
    manifest['records']=[record,copy.deepcopy(record)]
    malformed = drawing+MARKER+json.dumps(manifest)
    with pytest.raises(ValueError,match='Aggregate native component count'):from_ascii(malformed)
    record['definition']['members']=[{**template,'bits':1000000,'input_bits':1000001}]
    manifest['records']=[record]
    malformed = drawing+MARKER+json.dumps(manifest)
    with pytest.raises(ValueError,match='Aggregate native explicit bit expansion'):from_ascii(malformed)


def test_readable_public_api_has_all_members_and_optional_audit():
    ir=from_cipher(circuit())
    text=to_tikz(ir)
    assert 'Ordered input fragments' in text
    assert 'Operation / parameters' in _table_text(text)
    assert 'Computation overview' in text
    assert 'hypertarget' in text
    assert 'hyperlink' in text
    for index in range(len(ir['nodes'])):
        assert f'diagram-member-{index}' in text
    assert 'operand_positions' not in text
    assert '\\mbox{' in text
    audit=to_tikz(ir,audit=True)
    assert 'Optional audit' in audit
    assert 'operand' in audit
    assert 'round 0' in to_tikz(ir,view='overview')
    assert 'Round 0:' in to_tikz(ir,view='detail')
    with pytest.raises(ValueError,match='pages'):
        to_tikz(ir,maxPages=1)
    for options in ({'view':'template'},{'legend':'hidden'},{'tableLineBudget':0},
                    {'anchorPrefix':'bad\\input'},{'stageMode':'cipher-name'}):
        with pytest.raises(ValueError):to_tikz(ir,**options)


def test_vector_api_rejects_changed_actual_source_glyph(monkeypatch):
    import claasp.diagrams as diagrams
    ir=from_cipher(circuit());changed=copy.deepcopy(ir)
    changed['nodes'][0]['description']=['MODSUB',2,None]
    changed_text=diagrams.to_ascii(changed)
    import claasp.diagram_glyphs as glyphs
    encode_layout = glyphs._encode_layout
    def changed_export(*args, **kwargs):
        _, cells, dimensions = encode_layout(*args, **kwargs)
        return changed_text, cells, dimensions
    monkeypatch.setattr(glyphs, '_encode_layout', changed_export)
    with pytest.raises(ValueError,match='changed native IR'):
        diagrams.to_tikz(ir)


def test_readable_stride_and_member_compression_preserve_order_and_repeats():
    from claasp.diagram_presentation import selections,input_fragments
    def expand(value):
        result=[]
        for item in value.split(','):
            if ':' in item:
                start,step,end=map(int,item.split(':'));result.extend(range(start,end+(1 if step>0 else -1),step))
            else:result.append(int(item))
        return result
    for values in ([0,3,6,9],[9,6,3,0],[3,1,3,2,0],[0,0,1,2,3]):
        assert expand(selections(values))==list(values)
    operands=[{'source':f'arbitrary_{i}','positions':[2,0,2]} for i in range(5)]
    locations={f'arbitrary_{i}':('D5:7',i+1) for i in range(5)}
    text=input_fragments(operands,locations)
    assert '1..5: D5:7.members[1:1:5]' in text
    assert 'each [2,0,2]' in text
    renamed=[dict(e,source='renamed_'+str(i)) for i,e in enumerate(operands)]
    assert input_fragments(renamed,{e['source']:('D5:7',i+1) for i,e in enumerate(renamed)})==text


def test_readable_group_rotation_parameters_and_member_counts():
    c=Cipher('opaque','permutation',['value'],[8],8);c.add_round()
    nodes=[c.add_rotate_component(['value'],[[0,1,2,3]],4,-1),
           c.add_rotate_component(['value'],[[4,5,6,7]],4,-1)]
    c.add_cipher_output_component([n.id for n in nodes],[list(range(4))]*2,8)
    ir=from_cipher(c);text=to_tikz(ir,view='wires')
    assert 'ROTATE/4(-1) x2' in text
    assert text.count('diagram-member-')==len(ir['nodes'])
    assert from_ascii(to_ascii(ir))==ir


def test_readable_long_constants_are_complete_without_audit_and_empty_rounds_have_no_dead_links():
    c = Cipher('opaque', 'permutation', ['value'], [128], 128)
    c.add_round()
    constant = c.add_constant_component(128, 0x123456789abcdef0123456789abcdef0)
    c.add_cipher_output_component([constant.id], [list(range(128))], 128)
    c.add_round()
    ir = from_cipher(c)
    text = to_tikz(ir).replace(r'\allowbreak{}', '')
    assert 'CONST/128=P1' in text
    assert '0x123456789abcdef0123456789abcdef0' in text
    assert 'Optional audit' not in text
    assert 'round 1: 0 operations' in text
    assert r'\hyperlink{diagram-round-1}' not in text
    assert from_ascii(to_ascii(ir)) == ir


def test_overview_preserves_nonadjacent_dependencies_without_overlapping_arc_labels():
    from claasp.diagram_presentation import overview
    c = Cipher('opaque', 'permutation', ['value'], [4], 4)
    c.add_round()
    first = c.add_not_component(['value'], [list(range(4))], 4)
    c.add_round()
    c.add_not_component([first.id], [list(range(4))], 4)
    c.add_round()
    c.add_cipher_output_component([first.id], [list(range(4))], 4)
    ir = from_cipher(c)
    text = '\n'.join(overview(ir, {}, {}))
    assert 'Complete cross-stage dependencies' in text
    assert 'Adjacent-stage dependencies' in text
    assert '0 & 2 & 4' in _table_text(text)
    assert '(S0.east) to[bend left=25] node[right,font=\\scriptsize] {4 bits} (S2.east)' not in text
    assert '(S1.east);' in text


def test_unary_native_marker_is_not_presented_as_zero_operand_arity():
    from claasp.diagram_presentation import operation
    for name in ('NOT', 'REVERSE'):
        label = operation({'type': 'word_operation', 'description': [name, 0], 'bits': 17})
        assert label == name + '/17(unary)'
        assert 'arity=0' not in label


def test_readable_observation_and_final_output_tags_survive_escaping_and_wrapping():
    from claasp.diagram_presentation import escape
    c = Cipher('opaque', 'permutation', ['value'], [4], 4)
    c.add_round()
    tags = ['UNIQUE_STATE_TAG_a&b_%#{}', 'SECOND_STATE_' + 'long_token_' * 15]
    for tag in tags:
        c.add_intermediate_output_component(['value'], [list(range(4))], 4, tag)
    c.add_cipher_output_component(['value'], [list(range(4))], 4)
    ir = from_cipher(c)
    final_tag = 'FINAL_TAG_$^~' + 'final_long_' * 10
    ir['nodes'][-1]['description'] = [final_tag]
    for view in ('overview-detail', 'detail'):
        text = _table_text(to_tikz(ir, view=view))
        for tag in tags + [final_tag]:
            assert escape(tag) in text
        assert 'OBSERVE/4 tag=P1' in text
        assert 'OBSERVE/4 tag=P2' in text
        assert 'OUT/4 tag=P3' in text
        assert 'Optional audit' not in text
    assert from_ascii(to_ascii(ir)) == ir


def test_state_indices_reserve_a_lane_between_value_rows():
    import re
    c = Cipher('index_probe', 'permutation', ['data'], [2], 2)
    c.add_round()
    c.add_cipher_output_component(['data'], [[0, 1]], 2)
    text = state_tikz(from_cipher(c), columns=1)
    centers = [float(y) for y in re.findall(r'minimum height=0.5cm.*at \(0,([^)]*)\)', text)]
    # Adjacent values need their .5 cm boxes plus a lane for the tiny index.
    assert centers == [0.0, -0.75]
    ir = from_cipher(c)
    with pytest.raises(ValueError, match='index labels'):
        state_tikz(ir, columns=1, row_gap=0)


def test_readable_serial_arithmetic_wraps_all_columns_and_retains_every_member():
    c = Cipher('serial_probe', 'permutation', ['data'], [32], 32)
    c.add_round()
    source = 'data'
    for _ in range(34):
        source = c.add_modadd_component([source, 'data'], [list(range(32))]*2, 32).id
    c.add_cipher_output_component([source], [list(range(32))], 32)
    text = to_tikz(from_cipher(c), view='detail')
    visible = _table_text(text)
    for ordinal in range(34):
        assert f'{ordinal}: modadd\\_0\\_{ordinal}' in visible
    assert '34: cipher\\_output\\_0\\_34' in visible
    assert r'\fontfamily{cmtt}\fontsize{9}{11}' in text
    assert r'\noindent\begin{tabular}' in text


def test_default_vector_export_searches_once_parses_actual_text_once_and_skips_wires(monkeypatch):
    import claasp.diagram_glyphs as glyphs
    counts = {'layouts': 0, 'parses': 0}
    build, decode = glyphs.build_grid, glyphs.decode
    def counted_layout(*args, **kwargs):
        counts['layouts'] += 1
        return build(*args, **kwargs)
    def counted_decode(text, **kwargs):
        counts['parses'] += 1
        assert '# CLAASP-TYPED-GLYPH 1' in text
        return decode(text, **kwargs)
    def unwanted_panel(*args, **kwargs):
        pytest.fail('A summary/detail export must not construct wire panels')
    monkeypatch.setattr(glyphs, 'build_grid', counted_layout)
    monkeypatch.setattr(glyphs, 'decode', counted_decode)
    monkeypatch.setattr(glyphs, '_wire_panel', unwanted_panel)
    text = to_tikz(from_cipher(circuit()))
    assert 'Computation overview:' in text
    assert counts['layouts'] == 1
    assert counts['parses'] == 1


def test_ready_heap_defers_constants_until_a_consumer_can_progress():
    from claasp.diagram_glyphs import _ReadyCalls, _call_consumers
    calls = [{'args': args} for args in [[], [], [('input', 0)],
             [('call', 0), ('call', 0), ('call', 2)], [('call', 1), ('call', 3)], []]]
    pending = set(range(len(calls)))
    queue = _ReadyCalls(calls, _call_consumers(calls), {('input', 0)}, pending, set(), lambda i: (i,))
    order = []
    while pending:
        index = queue.next()
        pending.remove(index)
        order.append(index)
        queue.publish(('call', index))
    assert order == [2, 0, 3, 1, 4, 5]


@pytest.mark.parametrize('seed', [19, 43, 97])
def test_branching_rounds_match_independent_bit_arithmetic(seed):
    import random
    rng = random.Random(seed)
    c = Cipher('branch_probe', 'permutation', ['a', 'b'], [8, 8], 24)
    c.add_round()
    ids, functions = ['a', 'b'], [lambda a, b: a, lambda a, b: b]
    for index in range(48):
        if index and index % 12 == 0:
            c.add_round()
        left, right = rng.randrange(len(ids)), rng.randrange(len(ids))
        f, g = functions[left], functions[right]
        positions = [list(range(8)), list(reversed(range(8)))]
        # Reverse the second selected bit stream independently of the native backend.
        selected_g = lambda a, b, g=g: int(f'{g(a, b):08b}'[::-1], 2)
        if index % 4 == 0:
            value = rng.randrange(256)
            node = c.add_constant_component(8, value)
            function = lambda a, b, value=value: value
        elif index % 4 == 1:
            node = c.add_modsub_component([ids[left], ids[right]], positions, 8)
            function = lambda a, b, f=f, g=selected_g: (f(a, b)-g(a, b)) & 255
        elif index % 4 == 2:
            node = c.add_xor_component([ids[left], ids[right]], positions, 8)
            function = lambda a, b, f=f, g=selected_g: f(a, b)^g(a, b)
        else:
            node = c.add_rotate_component([ids[left]], [list(range(8))], 8, -1)
            function = lambda a, b, f=f: ((f(a, b)<<1)|(f(a, b)>>7)) & 255
        ids.append(node.id)
        functions.append(function)
    selected = [len(ids)-1, len(ids)-7, len(ids)-13]
    c.add_cipher_output_component([ids[i] for i in selected], [list(range(8))]*3, 24)
    ir = from_cipher(c)
    drawing = to_ascii(ir)
    restored = to_cipher(from_ascii(drawing))
    for a, b in [(0, 0), (255, 1), (0x83, 0x35), (1, 255)]:
        expected = 0
        for index in selected:
            expected = (expected << 8) | functions[index](a, b)
        assert restored.evaluate([a, b]) == expected
    renamed = copy.deepcopy(ir)
    names = {item['id']: f'v{i}' for i, item in enumerate(renamed['inputs']+renamed['nodes'])}
    for item in renamed['inputs']+renamed['nodes']:
        item['id'] = names[item['id']]
    for node in renamed['nodes']:
        for operand in node['operands']:
            operand['source'] = names[operand['source']]
    assert to_ascii(renamed).split('# CLAASP-TYPED-GLYPH 1')[0] == drawing.split('# CLAASP-TYPED-GLYPH 1')[0]
