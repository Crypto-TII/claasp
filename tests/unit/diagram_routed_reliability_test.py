"""Normal multiround cipher and word-graph reliability regressions."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import Diagrams,from_ascii,to_ascii,to_cipher
from claasp.cipher_modules.diagram.word_visual import build,evaluate,input_words
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher
ROOT=Path(__file__).resolve().parents[2]


def reference_feistel(plaintext,key,rounds,simeck=False):
    """Independent16-bit rounds; Simeck's declared16-bit z-sequence is literal."""
    mask=65535
    def left(value,amount):return ((value<<amount)|(value>>(16-amount)))&mask
    def nonlinear(value):
        return (value&left(value,5))^left(value,1) if simeck else (left(value,1)&left(value,8))^left(value,2)
    x,y=plaintext>>16,plaintext&mask
    words=[(key>>(16*(3-i)))&mask for i in range(4)]
    for stage in range(rounds):
        round_key=words[3] if simeck else (key>>(16*stage))&mask
        x,y=(y^nonlinear(x)^round_key)&mask,x
        if simeck:
            constant=65532^((5557826286501673759>>stage)&1)
            words=[(words[3]^nonlinear(words[2])^constant)&mask,words[0],words[1],words[2]]
    return (x<<16)|y


@pytest.mark.parametrize('factory,rounds',[(SimonBlockCipher,n) for n in (2,3,4)]
                         +[(SimeckBlockCipher,n) for n in (2,3,4,6)])
def test_normal_multiround_ciphers_native_glyph_and_integer_agreement(factory,rounds):
    cipher=factory(block_bit_size=32,key_bit_size=64,number_of_rounds=rounds)
    diagram=Diagrams(cipher);ir=diagram.ir
    annotated=diagram.to_ascii(routed_words=True,annotations=True)
    assert from_ascii(annotated)==ir
    assert diagram.to_ascii(routed_words=True,annotations=True)==annotated
    body=diagram.to_ascii(routed_words=True);model=build(ir,routed_words=True)
    assert diagram.to_tikz(routed_words=True)==diagram.to_tikz(routed_words=True)
    restored=to_cipher(from_ascii(annotated))
    for plaintext,key in [(0,0),(0xffffffff,0xffffffffffffffff),(0x6574694c,0x1918111009080100)]:
        by_name={'plaintext':plaintext,'key':key};inputs=[by_name[n['id']] for n in ir['inputs']]
        expected=reference_feistel(plaintext,key,rounds,factory is SimeckBlockCipher)
        assert cipher.evaluate(inputs)==restored.evaluate(inputs)==expected
        assert evaluate(body,input_words(model,ir,inputs),16,model['cipher_columns'])['cipher']==expected


@pytest.mark.parametrize('rounds',[5,6])
def test_simon_key_schedule_four_port_node_remains_explicitly_unsupported(rounds):
    diagram=Diagrams(SimonBlockCipher(block_bit_size=32,key_bit_size=64,number_of_rounds=rounds))
    assert min(n['round'] for n in diagram.ir['nodes'] if n['description']==['XOR',4])==4
    assert any(n['description']==['XOR',4] for n in diagram.ir['nodes'])
    with pytest.raises(ValueError,match='physical port arity'):
        diagram.to_ascii(routed_words=True)


def duplicate_branches():
    cipher=Cipher('duplicate_branches','permutation',['a','b','c'],[8]*3,24);cipher.add_round()
    first=cipher.add_rotate_component(['a'],[list(range(8))],8,-3)
    second=cipher.add_rotate_component(['a'],[list(range(8))],8,-3)
    addition=cipher.add_modadd_component([first.id,'b'],[list(range(8))]*2,8)
    boolean=cipher.add_xor_component([second.id,'c','a'],[list(range(8))]*3,8)
    cipher.add_cipher_output_component([addition.id,boolean.id,'a'],[list(range(8))]*3,24)
    return cipher


def test_upstream_identical_branches_follow_downstream_semantics_not_ids_or_order():
    diagram=Diagrams(duplicate_branches());ir=diagram.ir
    original=diagram.to_ascii(routed_words=True)
    changed=copy.deepcopy(ir);changed['nodes'][0],changed['nodes'][1]=changed['nodes'][1],changed['nodes'][0]
    assert to_ascii(changed,routed_words=True)==original
    names={n['id']:f'name_{i}' for i,n in enumerate(changed['inputs']+changed['nodes'])}
    for node in changed['inputs']+changed['nodes']:
        node['id']=names[node['id']]
        for edge in node.get('operands',[]):edge['source']=names[edge['source']]
    assert to_ascii(changed,routed_words=True)==original
    assert from_ascii(to_ascii(changed,routed_words=True,annotations=True))==changed


def test_layout_and_annotations_match_across_two_fresh_hash_seed_processes():
    source=Path(__file__).read_text()
    begin=source.index('def duplicate_branches():');end=source.index('\n\ndef test_',begin)
    program=('import hashlib,json\nfrom claasp.cipher import Cipher\nfrom claasp.diagrams import Diagrams\n'
             +source[begin:end]+"\ndiagram=Diagrams(duplicate_branches())\n"
             +"print(json.dumps([hashlib.sha256(diagram.to_ascii(routed_words=True,annotations=value).encode()).hexdigest() for value in (False,True)]))")
    outputs=[]
    for seed in ('0','1'):
        environment=dict(os.environ,PYTHONHASHSEED=seed,PYTHONPATH=str(ROOT))
        completed=subprocess.run([sys.executable,'-c',program],env=environment,check=True,
                                 capture_output=True,text=True,timeout=20)
        outputs.append(json.loads(completed.stdout))
    assert outputs[0]==outputs[1]


def ordinary_words(bits,rounds):
    cipher=Cipher('ordinary_words','permutation',['a','b','c'],[bits]*3,bits*3)
    words=['a','b','c']
    for stage in range(rounds):
        cipher.add_round()
        rotate=cipher.add_rotate_component([words[0]],[list(range(bits))],bits,-(stage+1))
        addition=cipher.add_modadd_component([words[0],rotate.id],[list(range(bits))]*2,bits)
        subtraction=cipher.add_modsub_component([words[1],words[2]],[list(range(bits))]*2,bits)
        boolean=cipher.add_xor_component([words[2],words[0],subtraction.id],[list(range(bits))]*3,bits)
        words=[addition.id,subtraction.id,boolean.id]
        if stage+1<rounds:cipher.add_round_output_component(words,[list(range(bits))]*3,bits*3)
    cipher.add_cipher_output_component(words,[list(range(bits))]*3,bits*3)
    return cipher


@pytest.mark.parametrize('bits,rounds',[(4,1),(8,2),(8,4),(16,3)])
def test_ordinary_word_graphs_keep_ordered_arithmetic_and_live_fanout(bits,rounds):
    cipher=ordinary_words(bits,rounds);diagram=Diagrams(cipher);ir=diagram.ir
    body=diagram.to_ascii(routed_words=True)
    annotated=diagram.to_ascii(routed_words=True,annotations=True)
    assert from_ascii(annotated)==ir
    model=build(ir,routed_words=True);restored=to_cipher(from_ascii(annotated));mask=(1<<bits)-1
    for initial in [[0,0,0],[mask,mask,mask],[1,2,3]]:
        a,b,c=initial
        for stage in range(rounds):
            amount=(stage+1)%bits;rot=((a<<amount)|(a>>(bits-amount)))&mask
            a,b,c=(a+rot)&mask,(b-c)&mask,(c^a^((b-c)&mask))&mask
        expected=(a<<(2*bits))|(b<<bits)|c
        assert cipher.evaluate(initial)==restored.evaluate(initial)==expected
        assert evaluate(body,input_words(model,ir,initial),bits,model['cipher_columns'])['cipher']==expected
    assert diagram.to_ascii(routed_words=True)==body
