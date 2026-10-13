"""Public word-view behavior and explicit historical serializer compatibility."""
import copy
import pytest
from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher, synthesis_report
from claasp.cipher_modules.diagram.manual_blocks import encode as legacy_encode
from claasp.cipher_modules.diagram.word_bindings import MARKER
from claasp.cipher_modules.diagram.word_visual import parse, evaluate, build, input_words


@pytest.mark.parametrize('rounds', [1, 2])
@pytest.mark.parametrize('side', ['right', 'left'])
def test_annotations_preserve_default_picture_and_cipher_display_roles(rounds, side):
    cipher = SpeckBlockCipher(number_of_rounds=rounds)
    ir = from_cipher(cipher)
    body = to_ascii(ir, key_side=side)
    annotated = to_ascii(ir, key_side=side, annotations=True)
    assert annotated.split(MARKER)[0] == body
    assert from_ascii(annotated) == ir
    parsed = parse(body)
    assert len(parsed['inputs']) == len(parsed['outputs']) == 6
    assert sum(parsed['cells'][key]['secret'] for key in parsed['inputs']) == 4
    assert not any(token in body for token in ('DATA', 'KEY', 'UNUSED', 'SEL', 'JOIN', 'OBS', 'OUT'))
    model = build(ir, key_side=side)
    for values in ([0x12345678, 0x0123456789ABCDEF], [0x9ABCDEF0, 0xF1E2D3C4B5A69788]):
        result = evaluate(body, input_words(model, ir, values), 16, model['cipher_columns'])
        assert result['cipher'] == cipher.evaluate(values)
        assert to_cipher(from_ascii(annotated)).evaluate(values) == result['cipher']
    assert to_cipher(from_ascii(annotated)).output_bit_size == 32
    report = synthesis_report(ir, key_side=side)
    assert report['view'] == 'persistent-word'
    assert report['fallback_reason'] is None
    assert report['metrics']['width'] == model['columns']


@pytest.mark.parametrize('annotated', [False, True])
def test_explicit_legacy_serializer_retains_exact_old_bytes(annotated):
    ir = from_cipher(SpeckBlockCipher(number_of_rounds=1))
    assert to_ascii(ir, format='human-legacy', annotations=annotated) == legacy_encode(ir, annotations=annotated)


def test_fallback_is_independent_of_annotations_and_is_reported():
    cipher = Cipher('shape_probe', 'permutation', ['a'], [8], 4)
    cipher.add_round()
    cipher.add_cipher_output_component(['a'], [[0, 1, 2, 3]], 4)
    ir = from_cipher(cipher)
    assert to_ascii(ir, word_bits=4) == legacy_encode(ir, word_bits=4)
    assert to_ascii(ir, word_bits=4, annotations=True) == legacy_encode(ir, word_bits=4, annotations=True)
    assert from_ascii(to_ascii(ir, word_bits=4, annotations=True)) == ir
    report = synthesis_report(ir, word_bits=4)
    assert report['view'] == 'human-legacy'
    assert 'unequal shape' in report['fallback_reason']


def test_native_call_budget_counts_transparent_boundaries():
    cipher = Cipher('budget_probe', 'permutation', ['a'], [4], 4)
    cipher.add_round()
    cipher.add_cipher_output_component(['a'], [list(range(4))], 4)
    ir = from_cipher(cipher)
    observed = copy.deepcopy(ir['nodes'][0])
    observed.update(id='observation', type='intermediate_output', description=['state'])
    ir['nodes'].insert(0, observed)
    with pytest.raises(ValueError, match='max_calls'):
        to_ascii(ir, max_calls=1)


def test_persistent_parser_rejects_broken_interior_glyph():
    ir = from_cipher(SpeckBlockCipher(number_of_rounds=1))
    lines = to_ascii(ir).splitlines()
    assert lines[12][13] == '-'
    lines[12] = lines[12][:13]+' '+lines[12][14:]
    with pytest.raises(ValueError, match='complete glyph'):
        parse('\n'.join(lines)+'\n')
