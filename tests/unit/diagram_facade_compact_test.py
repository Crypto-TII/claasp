"""Public facade, accepted output fixtures, and generic unary compatibility."""
import copy
import importlib.util
from pathlib import Path
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import Diagrams, from_cipher, from_ascii, to_ascii, to_tikz, state_tikz
from claasp.cipher_modules.diagram.word_visual import build
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('rounds', [1,2])
@pytest.mark.parametrize('side', ['right','left'])
def test_accepted_speck_ascii_and_vector_bytes_remain_frozen(rounds, side):
    diagram = Diagrams(SpeckBlockCipher(number_of_rounds=rounds))
    base = ROOT/'tests/fixtures/accepted_speck'/f'speck{rounds}-{side}'
    assert diagram.to_ascii(key_side=side).encode() == base.with_suffix('.asciiart').read_bytes()
    assert diagram.to_tikz(key_side=side, fitToPage=(25,18)).encode() == base.with_suffix('.tikz').read_bytes()


def test_facade_freezes_native_graph_and_preserves_functional_api():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    diagram = Diagrams(cipher)
    ir = diagram.ir
    ir['name'] = 'outside_edit'
    assert diagram.ir['name'] != 'outside_edit'
    cipher.add_round()
    assert diagram.ir['rounds'] == 1
    assert diagram.to_ascii() == to_ascii(diagram.ir)
    assert diagram.to_tikz(fitToPage=(25,30)) == to_tikz(diagram.ir,fitToPage=(25,30))
    values = diagram.evaluate_state_values([0x6574694c,0x1918111009080100])
    assert diagram.to_cipher().evaluate([0x6574694c,0x1918111009080100]) == 0x5316f627
    assert diagram.state_tikz(mode='word',word_bits=None,values=values) == state_tikz(diagram.ir,mode='word',word_bits=None,values=values)
    assert len(diagram.state_snapshots(mode='word',word_bits=None)) == 2
    assert diagram.state_ascii(mode='word',word_bits=None)
    assert diagram.state_view()


def test_full_two_rounds_have_eight_real_four_way_rotation_cohorts():
    cipher = ChachaPermutation(number_of_rounds=2,round_mode='single')
    ir = from_cipher(cipher)
    model = build(ir,parallel_unary=4)
    rotations = [r for r in model['records'] if r['definition']['description'][0]=='ROTATE']
    cohorts = {r['row'] for r in rotations}
    assert len(rotations) == 32 and len(cohorts) == 8
    assert all(sum(r['row']==row for r in rotations)==4 for row in cohorts)
    assert len(model['records']) == 96
    assert from_ascii(to_ascii(ir,parallel_unary=4,annotations=True)) == ir
    assert [f['stage'] for f in Diagrams(cipher).state_snapshots(mode='word',word_bits=None)] == [-1,0,1,2,3]


def _parallel_graph(rotations=(3,3,3,3), rounds=(0,0,0,0)):
    cipher = Cipher('generic_unary', 'permutation', ['data'], [32], 32)
    ids = []
    for stage in range(max(rounds)+1):
        cipher.add_round()
        for index, amount in enumerate(rotations):
            if rounds[index]==stage:
                node=cipher.add_rotate_component(['data'],[list(range(index*8,(index+1)*8))],8,amount)
                ids.append((index,node.id))
    cipher.add_cipher_output_component([node for _,node in sorted(ids)],[list(range(8))]*4,32)
    return from_cipher(cipher)


def test_compatibility_includes_parameters_and_round_boundaries():
    for rotations,rounds in [((3,3,3,3),(0,0,0,0)),((3,4,3,4),(0,0,0,0)),((3,3,3,3),(0,0,1,1))]:
        ir = _parallel_graph(rotations,rounds)
        model = build(ir,parallel_unary=4)
        by_row = {}
        for record in model['records']:
            definition=record['definition']
            by_row.setdefault(record['row'],[]).append((definition['round'],tuple(definition['description'])))
        assert all(len(set(facts))==1 for facts in by_row.values())
        assert from_ascii(to_ascii(ir,parallel_unary=4,annotations=True)) == ir


def test_independent_constructor_order_and_identifiers_do_not_select_layout():
    ir = _parallel_graph()
    changed = copy.deepcopy(ir)
    changed['nodes'][:-1] = list(reversed(changed['nodes'][:-1]))
    assert to_ascii(changed,parallel_unary=4) == to_ascii(ir,parallel_unary=4)
    renamed = copy.deepcopy(changed)
    names = {n['id']:f'value_{i}' for i,n in enumerate(changed['inputs']+changed['nodes'])}
    for node in renamed['inputs']+renamed['nodes']:
        node['id'] = names[node['id']]
        for edge in node.get('operands',[]):edge['source'] = names[edge['source']]
    assert to_ascii(renamed,parallel_unary=4) == to_ascii(ir,parallel_unary=4)
    assert from_ascii(to_ascii(renamed,parallel_unary=4,annotations=True)) == renamed


@pytest.mark.parametrize('maximum', [False,0,-1,2.5])
def test_invalid_parallel_cap_rejects(maximum):
    with pytest.raises(ValueError):to_ascii(_parallel_graph(),parallel_unary=maximum)


def test_real_quarter_round_has_four_words_twelve_operations_and_integer_values():
    spec = importlib.util.spec_from_file_location('quarter_round_example',ROOT/'docs/diagrams/examples/quarter_round.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    cipher = module.quarter_round();diagram=Diagrams(cipher)
    model = build(diagram.ir,parallel_unary=4)
    assert len(model['primary']) == 4 and len(model['records']) == 12
    assert [r['definition']['description'][1] for r in model['records'] if r['definition']['description'][0]=='ROTATE'] == [-16,-12,-8,-7]
    words = [0x11111111,0x01020304,0x9b8d6f43,0x01234567]
    value=int(''.join(f'{word:08x}' for word in words),16)
    assert cipher.evaluate([value]) == int('ea2a92f4cb1cf8ce4581472e5881c4bb',16)
    assert from_ascii(diagram.to_ascii(parallel_unary=4,annotations=True)) == diagram.ir


def _half_quarter(words, indices, rotations):
    a,b,c,d = indices
    mask = 0xffffffff
    def left(value, amount):return ((value << amount) | (value >> (32-amount))) & mask
    words[a] = (words[a]+words[b]) & mask
    words[d] = left(words[d]^words[a], rotations[0])
    words[c] = (words[c]+words[d]) & mask
    words[b] = left(words[b]^words[c], rotations[1])


def test_two_full_rounds_values_boundaries_and_fresh_export_are_independent():
    cipher=ChachaPermutation(number_of_rounds=2,round_mode='single')
    diagram=Diagrams(cipher)
    text=diagram.to_ascii(parallel_unary=4,annotations=True)
    ir=from_ascii(text)
    for _ in range(3):
        text=to_ascii(ir,parallel_unary=4,annotations=True)
        assert from_ascii(text)==diagram.ir
    rebuilt=Diagrams(cipher).to_cipher()
    for initial in [list(range(16)),[0xffffffff]*16,[(i*0x1234567)&0xffffffff for i in range(16)]]:
        value=int(''.join(f'{word:08x}' for word in initial),16)
        frames=diagram.state_snapshots(mode='word',word_bits=None,values=diagram.evaluate_state_values([value]))
        words=initial.copy()
        cohorts=[[(i,i+4,i+8,i+12) for i in range(4)],[(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]]
        for stage in range(4):
            for indices in cohorts[stage//2]:_half_quarter(words,indices,(16,12) if stage%2==0 else (8,7))
            assert [word['value'] for word in frames[stage+1]['words']] == words
        expected=int(''.join(f'{word:08x}' for word in words),16)
        from claasp.diagrams import to_cipher
        assert cipher.evaluate([value])==rebuilt.evaluate([value])==to_cipher(ir).evaluate([value])==expected


def test_full_dependency_layer_reordering_and_renaming_preserve_actual_layout():
    ir=from_cipher(ChachaPermutation(number_of_rounds=2,round_mode='single'))
    depths={n['id']:0 for n in ir['inputs']}
    indices={n['id']:i for i,n in enumerate(ir['nodes'])}
    for node in ir['nodes']:
        depths[node['id']]=1+max((depths[e['source']] for e in node['operands']),default=0)
    reordered=copy.deepcopy(ir)
    reordered['nodes'].sort(key=lambda n:(n['round'],depths[n['id']],-indices[n['id']]))
    assert to_ascii(reordered,parallel_unary=4)==to_ascii(ir,parallel_unary=4)
    names={n['id']:f'v_{i}' for i,n in enumerate(reordered['inputs']+reordered['nodes'])}
    for node in reordered['inputs']+reordered['nodes']:
        node['id']=names[node['id']]
        for edge in node.get('operands',[]):edge['source']=names[edge['source']]
    assert to_ascii(reordered,parallel_unary=4)==to_ascii(ir,parallel_unary=4)
    assert from_ascii(to_ascii(reordered,parallel_unary=4,annotations=True))==reordered


@pytest.mark.parametrize('operation', ['rotate','shift','not'])
def test_admitted_single_component_primitives_have_independent_values(operation):
    from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
    from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
    from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
    cipher = {'rotate':lambda:RotateCipher(bit_size=32,rotation_amount=7),
              'shift':lambda:ShiftCipher(bit_size=32,shift_amount=7),
              'not':lambda:NotCipher(bit_size=32)}[operation]()
    diagram=Diagrams(cipher)
    from claasp.diagrams import to_cipher
    rebuilt=to_cipher(from_ascii(diagram.to_ascii(annotations=True)))
    for value in (0,0x12345678,0xffffffff):
        expected={'rotate':((value>>7)|(value<<25))&0xffffffff,
                  'shift':value>>7,'not':value^0xffffffff}[operation]
        assert cipher.evaluate([value])==rebuilt.evaluate([value])==expected
