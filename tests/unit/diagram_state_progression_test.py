"""Generic word-bank progression and persistent vector contract."""
import json
import re
import pytest
from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.diagrams import from_cipher, to_tikz, to_ascii, state_snapshots, state_tikz, evaluate_state_values


def subtraction(reverse=False):
    cipher = Cipher('generic_order', 'block_cipher', ['plaintext', 'key'], [8, 8], 8)
    cipher.add_round()
    ids = ['key', 'plaintext'] if reverse else ['plaintext', 'key']
    operation = cipher.add_modsub_component(ids, [list(range(8))]*2, 8)
    cipher.add_cipher_output_component([operation.id], [list(range(8))], 8)
    return cipher


@pytest.mark.parametrize('reverse', [False, True])
def test_both_subtraction_orders_have_visible_port_numbers(reverse):
    cipher = subtraction(reverse)
    ir = from_cipher(cipher)
    assert cipher.evaluate([3, 7]) == ((7-3) if reverse else (3-7)) % 256
    text = to_tikz(ir)
    ports = [json.loads(line.removeprefix('% word-operand ')) for line in text.splitlines() if line.startswith('% word-operand ')]
    assert [(p['operand'], p['side']) for p in ports] == ([(1, 'right'), (2, 'top')] if reverse else [(1, 'top'), (2, 'right')])
    assert re.search(r'\\node\[font=\\tiny,.*\{1\};', text)
    assert re.search(r'\\node\[font=\\tiny,.*\{2\};', text)
    assert ('@21' in to_ascii(ir)) == reverse


def test_default_is_persistent_and_audit_is_explicit():
    ir = from_cipher(SpeckBlockCipher(number_of_rounds=1))
    assert to_tikz(ir) == to_tikz(ir, layoutSource='persistent')
    assert '% word-native ' not in to_tikz(ir, layoutSource='audit')
    with pytest.raises(ValueError, match="layoutSource='audit'"):
        to_tikz(ir, view='overview')
    c = Cipher('partial', 'permutation', ['a'], [8], 4)
    c.add_round();c.add_cipher_output_component(['a'], [[0,1,2,3]], 4)
    with pytest.raises(ValueError, match="layoutSource='audit'"):
        to_tikz(from_cipher(c))


@pytest.mark.parametrize('rounds', [1, 2])
def test_speck_round_state_matches_independent_integer_rounds(rounds):
    cipher = SpeckBlockCipher(number_of_rounds=rounds)
    ir = from_cipher(cipher)
    inputs = [0x6574694c, 0x1918111009080100]
    values = evaluate_state_values(cipher, inputs)
    frames = state_snapshots(ir, mode='word', word_bits=None, values=values)
    assert len(frames) == rounds+1 and all(len(f['words']) == 6 for f in frames)
    x,y = inputs[0] >> 16, inputs[0] & 65535
    k = 0x0100;l = [0x0908, 0x1110, 0x1918]
    for index, frame in enumerate(frames[1:]):
        if index:
            z = (((l[index-1] >> 7) | (l[index-1] << 9)) + k) & 65535
            z ^= index-1
            k = (((k << 2) | (k >> 14)) & 65535) ^ z
        x = ((((x >> 7) | (x << 9)) + y) & 65535) ^ k
        y = (((y << 2) | (y >> 14)) & 65535) ^ x
        assert [w['value'] for w in frame['words'][:2]] == [x,y]
    operations = state_snapshots(ir, mode='word', word_bits=None, values=values, granularity='operation')
    assert len(operations) == 1+frames[-1]['native_state_updates']
    assert all(not f['omitted_intra_round_steps'] for f in operations)
    reversed_frames = state_snapshots(ir, mode='word', word_bits=None, values=values, order='reverse')
    assert [w['value'] for w in reversed_frames[-1]['words']] == [w['value'] for w in reversed(frames[-1]['words'])]
    assert [w['role'] for w in frames[0]['words']] == ['data']*2+['key']*4


def test_chacha_generic_round_summary_and_balanced_full_overview():
    cipher = ChachaPermutation(number_of_rounds=1)
    ir = from_cipher(cipher)
    frames = state_snapshots(ir, mode='word', word_bits=None, columns=4)
    assert len(frames) == 3 and all(len(f['words']) == 16 for f in frames)
    assert all(f['geometry'] == 'explicit-columns' and f['omitted_intra_round_steps'] for f in frames)
    text = to_tikz(ir, pageBreaks=True)
    assert re.findall(r'rows (\d+):(\d+)', text) == [('0','17'),('17','34'),('34','50')]
    overview = to_tikz(ir, fitToPage=(25,18))
    assert overview.count('begin{tikzpicture}') == 1
    assert overview.count('% word-native ') == text.count('% word-native ') == 48
    assert 'intra-round steps omitted' in state_tikz(ir, mode='word', word_bits=None, columns=4).replace(r'\allowbreak{}','')
    with pytest.raises(ValueError):to_tikz(ir, fitToPage=(0,18))


def test_chacha_round_values_match_independent_half_quarter_round_formulas():
    cipher = ChachaPermutation(number_of_rounds=1)
    ir = from_cipher(cipher)
    words = list(range(16))
    inputs = [int(''.join(f'{word:08x}' for word in words), 16)]
    frames = state_snapshots(ir, mode='word', word_bits=None, values=evaluate_state_values(cipher, inputs))
    def rotate(value, amount):
        return ((value << amount) | (value >> (32-amount))) & 0xffffffff
    for stage, rotations in enumerate(((16,12),(8,7))):
        for i in range(4):
            a,b,c,d = i,i+4,i+8,i+12
            words[a] = (words[a]+words[b]) & 0xffffffff
            words[d] = rotate(words[d]^words[a], rotations[0])
            words[c] = (words[c]+words[d]) & 0xffffffff
            words[b] = rotate(words[b]^words[c], rotations[1])
        assert [word['value'] for word in frames[stage+1]['words']] == words
    assert cipher.evaluate(inputs) == int(''.join(f'{word:08x}' for word in words),16)


def test_word_states_are_identifier_renaming_invariant_and_capture_is_opt_in():
    import copy
    from claasp.cipher_modules.diagram.word_visual import build
    ir = from_cipher(SpeckBlockCipher(number_of_rounds=2))
    renamed = copy.deepcopy(ir)
    identities = {node['id']:f'value_{i}' for i,node in enumerate(ir['inputs']+ir['nodes'])}
    for node in renamed['inputs']+renamed['nodes']:
        node['id'] = identities[node['id']]
        for edge in node.get('operands',[]):edge['source'] = identities[edge['source']]
    before = state_snapshots(ir, mode='word', word_bits=None, granularity='operation')
    after = state_snapshots(renamed, mode='word', word_bits=None, granularity='operation')
    for a,b in zip(before,after):
        assert a['stage'] == b['stage'] and a['geometry'] == b['geometry']
        for original,changed in zip(a['words'],b['words']):
            assert changed['positions'] == [(identities[source],bit) for source,bit in original['positions']]
            assert changed['role'] == original['role']
    assert len(before) == len(after)
    assert build(ir)['state_frames'] == []
    assert len(build(ir,capture_states=True)['state_frames']) == len(before)


def test_round_boundaries_with_no_word_operation_carry_state_explicitly():
    cipher = Cipher('carried_state', 'permutation', ['data'], [4], 4)
    cipher.add_round()
    cipher.add_round_output_component(['data'], [list(range(4))], 4)
    cipher.add_round()
    cipher.add_cipher_output_component(['data'], [list(range(4))], 4)
    frames = state_snapshots(from_cipher(cipher), mode='word', word_bits=None)
    assert [frame['stage'] for frame in frames] == [-1,0,1]
    assert all(frame['words'][0]['positions'] == [('data',bit) for bit in range(4)] for frame in frames)
