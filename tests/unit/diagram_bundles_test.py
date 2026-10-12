import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher, synthesis_report
from claasp.cipher_modules.diagram.manual_blocks import _WordGraph, infer_word_bits, MARKER


def tiny():
    c = Cipher('anonymous_bundle', 'permutation', ['a'], [32], 3)
    c.add_round()
    x = c.add_sbox_component(['a'], [[0,13,31]], 3, [0,7,6,3,4,2,5,1])
    c.add_intermediate_output_component(['a'], [list(range(32))], 32, 'trace')
    c.add_cipher_output_component([x.id], [list(range(3))], 3)
    return from_cipher(c, roles={'a':'data'})


def test_existing_visible_records_pack_widths_without_hidden_sources():
    ir = tiny()
    old = _WordGraph(ir, infer_word_bits(ir))
    new = _WordGraph(ir, 1, native_bundles=True)
    assert (len(old.inputs),len(old.calls)) == (32,41)
    assert (len(new.inputs),len(new.calls)) == (1,4)
    text = to_ascii(ir, annotations=True, native_bundles=True)
    assert from_ascii(text) == ir
    footer = json.loads(text.split(MARKER)[1])
    assert set(footer) == {'format','primitive','records'}
    assert {item['definition']['kind'] for item in footer['records']} <= {'input','native','selection','join','native_boundary','discard'}
    assert next(item['definition'] for item in footer['records'] if item['definition']['kind']=='input')['positions'] == list(range(32))
    for _ in range(3):
        assert to_ascii(from_ascii(text), annotations=True, native_bundles=True) == text
    restored = to_cipher(from_ascii(text))
    for value in [0,1,7,(1<<32)-1,0x12345678,0x80000001]:
        selected = sum(((value>>(31-p))&1) << (2-i) for i,p in enumerate([0,13,31]))
        assert restored.evaluate([value]) == [0,7,6,3,4,2,5,1][selected]
        assert restored.evaluate([value],intermediate_output=True)[1]['trace'][0] == value


def test_no_caps_are_raised_and_incompatible_packing_rejects():
    with pytest.raises(ValueError, match='max_calls'):
        to_ascii(tiny(), annotations=True, max_calls=4)
    assert from_ascii(to_ascii(tiny(), annotations=True, native_bundles=True, max_calls=4)) == tiny()
    with pytest.raises(ValueError, match='max_calls'):
        to_ascii(tiny(), annotations=True, native_bundles=True, max_calls=3)
    for options in [{'word_bits':1},{'projection':'wordwise'},{'lane_policy':'state'},{'native_bundles':1}]:
        with pytest.raises(ValueError, match='Native bundles'):
            to_ascii(tiny(), annotations=True, **{'native_bundles':True, **options})


def test_wider_input_masks_and_whole_observation_are_checked_from_text():
    text = to_ascii(tiny(), annotations=True, native_bundles=True)
    body, footer = text.split(MARKER)
    original = json.loads(footer)
    for kind, field, value in [('input','bits',31),('selection','positions',[0,13,32]),('native_boundary','bits',31)]:
        metadata = copy.deepcopy(original)
        next(record['definition'] for record in metadata['records'] if record['definition']['kind']==kind)[field] = value
        with pytest.raises(ValueError):
            from_ascii(body+MARKER+json.dumps(metadata))


def test_consistent_identifier_renaming_is_geometry_invariant():
    ir = tiny(); renamed = copy.deepcopy(ir)
    mapping = {'a':'fresh_input',**{node['id']:'fresh_'+str(index) for index,node in enumerate(ir['nodes'])}}
    renamed['name'] = 'fresh_name';renamed['inputs'][0]['id'] = mapping['a']
    for node in renamed['nodes']:
        node['id'] = mapping[node['id']]
        for edge in node['operands']: edge['source'] = mapping[edge['source']]
    old = to_ascii(ir,annotations=True,native_bundles=True)
    new = to_ascii(renamed,annotations=True,native_bundles=True)
    assert old.split(MARKER)[0] == new.split(MARKER)[0]
    assert from_ascii(new) == renamed
    assert synthesis_report(ir,native_bundles=True)['packing_policy'] == 'native-bundles'


def test_unaligned_unused_declaration_is_preserved_without_word_index_caption():
    c = Cipher('anonymous_unused_bundle', 'permutation', ['a','unused'], [32,7], 3)
    c.add_round()
    x = c.add_sbox_component(['a'], [[0,13,31]], 3, [0,7,6,3,4,2,5,1])
    c.add_cipher_output_component([x.id], [list(range(3))], 3)
    ir = from_cipher(c,roles={'a':'data','unused':'key'})
    text = to_ascii(ir,annotations=True,native_bundles=True)
    assert 'SUNUSED' in text and from_ascii(text) == ir
    restored = to_cipher(from_ascii(text))
    assert restored.evaluate([0,0]) == restored.evaluate([0,127]) == 0
    assert restored.evaluate([0x80000001,0]) == restored.evaluate([0x80000001,127]) == 2
