"""Generic real-word routing, native Boolean arity, and actual-wire semantics."""
import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import Diagrams, from_cipher, from_ascii, to_ascii, to_cipher
from claasp.cipher_modules.diagram.word_visual import build, evaluate, input_words
from claasp.cipher_modules.diagram.word_bindings import MARKER
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher
from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation


@pytest.mark.parametrize('factory,operation_count', [(SimonBlockCipher,6),(SimeckBlockCipher,5)])
def test_one_round_real_feistel_matches_integer_graph_and_fresh_routes(factory,operation_count):
    cipher=factory(block_bit_size=32,key_bit_size=64,number_of_rounds=1)
    diagram=Diagrams(cipher);ir=diagram.ir
    with pytest.raises(ValueError):diagram.to_ascii()
    model=build(ir,routed_words=True)
    assert len(model['records'])==operation_count
    text=diagram.to_ascii(routed_words=True,annotations=True)
    assert from_ascii(text)==ir
    for _ in range(3):
        text=to_ascii(from_ascii(text),routed_words=True,annotations=True)
        assert from_ascii(text)==ir
    restored=to_cipher(from_ascii(text))
    mask=65535
    def left(word,amount):return ((word<<amount)|(word>>(16-amount)))&mask
    for plaintext,key in [(0,0),(0xffffffff,0xffffffffffffffff),(0x6574694c,0x1918111009080100),(0x12345678,0x0123456789abcdef)]:
        x,y=plaintext>>16,plaintext&mask
        nonlinear=(left(x,1)&left(x,8))^left(x,2) if factory is SimonBlockCipher else (x&left(x,5))^left(x,1)
        expected=((y^nonlinear^(key&mask))<<16)|x
        values={'plaintext':plaintext,'key':key}
        inputs=[values[n['id']] for n in ir['inputs']]
        assert cipher.evaluate(inputs)==restored.evaluate(inputs)==expected
        body=diagram.to_ascii(routed_words=True)
        assert evaluate(body,input_words(model,ir,inputs),16,model['cipher_columns'])['cipher']==expected
        states=diagram.state_snapshots(mode='declared',word_bits=None,values=diagram.evaluate_state_values(inputs))
        final=[word['value'] for word in states[-1]['words']]
        assert final==[expected>>16,expected&mask]
    vector=diagram.to_tikz(routed_words=True)
    assert '{C0}' in vector and '{C1}' in vector and '{D}' in vector
    assert not any(label in vector for label in ('{SEL','{JOIN','{PERM','{OBS'))


def test_generic_fanout_three_ports_repeated_operands_and_renaming():
    cipher=Cipher('generic_branch','permutation',['a','b','c'],[4,4,4],12)
    cipher.add_round()
    rotated=cipher.add_rotate_component(['a'],[list(range(4))],4,-1)
    gate=cipher.add_xor_component(['a',rotated.id,'a'],[list(range(4))]*3,4)
    cipher.add_cipher_output_component([gate.id,'b','c'],[list(range(4))]*3,12)
    ir=from_cipher(cipher);model=build(ir,routed_words=True)
    body=to_ascii(ir,routed_words=True)
    for a in range(16):
        values=[a,7,3];expected=((((a<<1)|(a>>3))&15)<<8)|(7<<4)|3
        assert evaluate(body,input_words(model,ir,values),4,model['cipher_columns'])['cipher']==expected
        assert to_cipher(from_ascii(to_ascii(ir,routed_words=True,annotations=True))).evaluate(values)==expected
    renamed=copy.deepcopy(ir)
    names={n['id']:f'value_{i}' for i,n in enumerate(ir['inputs']+ir['nodes'])}
    for node in renamed['inputs']+renamed['nodes']:
        node['id']=names[node['id']]
        for edge in node.get('operands',[]):edge['source']=names[edge['source']]
    assert to_ascii(renamed,routed_words=True)==body
    assert from_ascii(to_ascii(renamed,routed_words=True,annotations=True))==renamed


def test_arithmetic_ternary_and_malformed_width_masks_still_reject():
    cipher=Cipher('three_arithmetic','permutation',['data'],[12],4)
    cipher.add_round()
    addition=cipher.add_modadd_component(['data']*3,[list(range(i*4,(i+1)*4)) for i in range(3)],4)
    cipher.add_cipher_output_component([addition.id],[list(range(4))],4)
    with pytest.raises(ValueError):to_ascii(from_cipher(cipher),routed_words=True)
    diagram=Diagrams(SimonBlockCipher(number_of_rounds=1))
    text=diagram.to_ascii(routed_words=True,annotations=True);body,footer=text.split(MARKER)
    for mutation in ('width','mask','glyph'):
        metadata=json.loads(footer)
        gate=next(record for record in metadata['operations'] if record['definition']['description']==['XOR',3])
        if mutation=='width':gate['definition']['input_bits']-=1
        elif mutation=='mask':gate['operand_positions'][0]=list(reversed(gate['operand_positions'][0]))
        else:
            row,col=gate['at'];lines=body.splitlines();index=row*5+2
            position=col*11+lines[index][col*11:col*11+11].index('^')
            lines[index]=lines[index][:position]+'|'+lines[index][position+1:];body='\n'.join(lines)+'\n'
        with pytest.raises(ValueError):from_ascii(body+MARKER+json.dumps(metadata))


@pytest.mark.parametrize('options', [{'routed_words':1},{'routed_words':True,'max_cells':7},
                                      {'routed_words':True,'max_grid_area':7}])
def test_routing_option_and_allocation_bounds_reject(options):
    with pytest.raises(ValueError):to_ascii(from_cipher(SimonBlockCipher(number_of_rounds=1)),**options)


def test_chaskey_default_is_a_real_admitted_additional_primitive():
    cipher=ChaskeyPiPermutation(number_of_rounds=1)
    diagram=Diagrams(cipher)
    assert len(build(diagram.ir)['records'])==14
    assert from_ascii(diagram.to_ascii(annotations=True))==diagram.ir
    assert diagram.to_tikz().count('begin{tikzpicture}')==1


def test_chaskey_native_halves_match_independent_integer_formulas():
    diagram=Diagrams(ChaskeyPiPermutation(number_of_rounds=1))
    mask=0xffffffff
    def left(value,amount):return ((value<<amount)|(value>>(32-amount)))&mask
    for initial in [list(range(4)),[mask]*4,[0x12345678,0x9abcdef0,0x11223344,0x55667788]]:
        value=int(''.join(f'{word:08x}' for word in initial),16)
        frames=diagram.state_snapshots(mode='word',word_bits=None,values=diagram.evaluate_state_values([value]))
        a,b,c,d=initial
        a=(a+b)&mask;b=left(b,5)^a;a=left(a,16)
        c=(c+d)&mask;d=left(d,8)^c
        assert [word['value'] for word in frames[1]['words']]==[a,b,c,d]
        a=(a+d)&mask;d=left(d,13)^a
        c=(c+b)&mask;b=left(b,7)^c;c=left(c,16)
        expected=int(''.join(f'{word:08x}' for word in [a,b,c,d]),16)
        assert [word['value'] for word in frames[2]['words']]==[a,b,c,d]
        assert diagram.to_cipher().evaluate([value])==expected


@pytest.mark.parametrize('operation', ['xor','and','or'])
def test_three_port_boolean_gates_use_actual_ordered_inputs(operation):
    cipher=Cipher('generic_three','permutation',['data'],[12],12)
    cipher.add_round()
    node=getattr(cipher,'add_'+operation+'_component')(['data']*3,[list(range(i*4,(i+1)*4)) for i in range(3)],4)
    cipher.add_cipher_output_component([node.id,'data','data'],[list(range(4)),list(range(4,8)),list(range(8,12))],12)
    ir=from_cipher(cipher);model=build(ir,routed_words=True)
    text=to_ascii(ir,routed_words=True,annotations=True);restored=to_cipher(from_ascii(text))
    body=to_ascii(ir,routed_words=True)
    for a,b,c in [(1,2,4),(15,3,6),(10,5,10),(0,15,15)]:
        output={'xor':a^b^c,'and':a&b&c,'or':a|b|c}[operation]
        expected=(output<<8)|(b<<4)|c;value=(a<<8)|(b<<4)|c
        assert evaluate(body,input_words(model,ir,[value]),4,model['cipher_columns'])['cipher']==expected
        assert restored.evaluate([value])==expected


@pytest.mark.parametrize('reverse', [False,True])
def test_routed_live_subtraction_preserves_actual_operand_order(reverse):
    cipher=Cipher('live_subtraction','permutation',['a','b','c'],[4,4,4],12)
    cipher.add_round()
    operation=cipher.add_modsub_component(['b','a'] if reverse else ['a','b'],[list(range(4))]*2,4)
    cipher.add_cipher_output_component([operation.id,'a','b'],[list(range(4))]*3,12)
    ir=from_cipher(cipher);model=build(ir,routed_words=True)
    text=to_ascii(ir,routed_words=True,annotations=True)
    assert from_ascii(text)==ir
    expected=((((7-3) if reverse else (3-7))&15)<<8)|(3<<4)|7
    assert to_cipher(from_ascii(text)).evaluate([3,7,1])==expected
    assert evaluate(to_ascii(ir,routed_words=True),input_words(model,ir,[3,7,1]),4,model['cipher_columns'])['cipher']==expected


def test_routed_feistel_dependency_order_is_layout_invariant():
    ir=from_cipher(SimonBlockCipher(number_of_rounds=1))
    depths={node['id']:0 for node in ir['inputs']}
    indices={node['id']:i for i,node in enumerate(ir['nodes'])}
    for node in ir['nodes']:
        depths[node['id']]=1+max((depths[edge['source']] for edge in node['operands']),default=0)
    changed=copy.deepcopy(ir)
    changed['nodes'].sort(key=lambda node:(node['round'],depths[node['id']],-indices[node['id']]))
    assert to_ascii(changed,routed_words=True)==to_ascii(ir,routed_words=True)
    assert from_ascii(to_ascii(changed,routed_words=True,annotations=True))==changed


@pytest.mark.parametrize('side', ['right','left'])
def test_routed_key_side_relocation_keeps_native_input_roles_and_values(side):
    cipher=SimonBlockCipher(number_of_rounds=1);ir=from_cipher(cipher)
    text=to_ascii(ir,routed_words=True,key_side=side,annotations=True)
    assert from_ascii(text)==ir
    values={'plaintext':0x6574694c,'key':0x1918111009080100}
    inputs=[values[node['id']] for node in ir['inputs']]
    assert to_cipher(from_ascii(text)).evaluate(inputs)==0xbdfd6574


def test_original_mask_may_span_three_actual_ports_only_with_one_source():
    cipher=Cipher('cross_ports','permutation',['data'],[12],12)
    cipher.add_round()
    gate=cipher.add_xor_component(['data'],[list(range(12))],4)
    cipher.add_cipher_output_component([gate.id,'data','data'],[list(range(4)),list(range(4,8)),list(range(8,12))],12)
    ir=from_cipher(cipher)
    assert from_ascii(to_ascii(ir,routed_words=True,annotations=True))==ir
    text=Diagrams(SimonBlockCipher(number_of_rounds=1)).to_ascii(routed_words=True,annotations=True)
    body,footer=text.split(MARKER);metadata=json.loads(footer)
    gate=next(record for record in metadata['operations'] if record['definition']['description']==['XOR',3])
    gate['operand_positions']=[list(range(48))]
    with pytest.raises(ValueError):from_ascii(body+MARKER+json.dumps(metadata))
