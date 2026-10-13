"""Persistent ASCII/vector identity and deliberate compatibility boundaries."""
import json
import re
import pytest
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.diagrams import from_cipher, to_tikz
from claasp.cipher_modules.diagram.word_visual import build


@pytest.mark.parametrize('rounds', [1, 2])
@pytest.mark.parametrize('side', ['right', 'left'])
def test_vector_reuses_all_actual_word_coordinates_and_parameters(rounds, side):
    ir = from_cipher(SpeckBlockCipher(number_of_rounds=rounds))
    model = build(ir, key_side=side)
    text = to_tikz(ir, layoutSource='persistent', key_side=side)
    records = [json.loads(line[len('% word-native '):]) for line in text.splitlines() if line.startswith('% word-native ')]
    expected = [{'row':r['row'], 'column':r['column'], 'definition':r['definition']} for r in model['records']]
    assert sorted(records, key=lambda r:(r['row'], r['column'])) == sorted(expected, key=lambda r:(r['row'], r['column']))
    names = re.findall(r'\\node\[draw,[^\n]*?\(([^)]+)\) at', text)
    assert len(names) == len(model['records'])+12
    assert text.count('{S};') == 4
    assert not any(label in text for label in ('{SEL', '{JOIN', '{OBS', '{OUT', '{DATA', '{KEY'))
    assert r'\textgreater{}\textgreater{}\textgreater{}7' in text
    assert r'\textless{}\textless{}\textless{}2' in text


def test_labels_and_wire_borders_change_only_vector_styling():
    ir = from_cipher(SpeckBlockCipher(number_of_rounds=1))
    before = to_tikz(ir, layoutSource='persistent')
    after = to_tikz(ir, layoutSource='persistent', operator_style='labels', wire_borders=True)
    records = lambda text: [line for line in text.splitlines() if line.startswith('% word-native ')]
    assert records(before) == records(after)
    assert '{XOR}' in after and '{MODA}' in after
    assert 'gray!40' in after and 'gray!40' not in before


@pytest.mark.parametrize('options', [{'boxWidth':2}, {'rowSpacing':0}, {'anchorPrefix':'bad{tex}'}, {'maxPanels':1,'rowsPerPanel':1}, {'legend':'full'}, {'max_text_bytes':1}])
def test_persistent_vector_bounds_and_incompatible_tables_reject(options):
    with pytest.raises(ValueError):
        to_tikz(from_cipher(SpeckBlockCipher(number_of_rounds=1)), layoutSource='persistent', **options)


def test_panels_use_paired_actual_edge_references():
    text = to_tikz(from_cipher(SpeckBlockCipher(number_of_rounds=1)), layoutSource='persistent', rowsPerPanel=3)
    assert text.count('{V3:0}') == 2
