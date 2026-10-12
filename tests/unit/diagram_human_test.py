import copy
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher
from claasp.cipher_modules.diagram.human import to_word_ascii


def toy(left='left', right='right'):
    cipher = Cipher('generic_probe', 'permutation', [left, right], [4, 4], 8)
    cipher.add_round()
    node = cipher.add_xor_component([left, right], [list(range(4))]*2, 4)
    cipher.add_cipher_output_component([node.id, right], [list(range(4))]*2, 8)
    return from_cipher(cipher)


def test_toy_is_deterministic_and_preserves_ir():
    ir = toy()
    before = copy.deepcopy(ir)
    text = to_word_ascii(ir)
    assert text == to_word_ascii(ir)
    assert ir == before
    assert '^<' in text and 'v' in text
    assert text.splitlines()[-1].index('out[0]') < text.splitlines()[-1].index('out[1]')


def test_identifier_renaming_preserves_geometry():
    original = to_word_ascii(toy()).splitlines()
    renamed = to_word_ascii(toy('opaque_long_identifier', 'z')).splitlines()
    assert original[2:] == renamed[2:]


def test_labels_and_borders_keep_operand_markers():
    text = to_word_ascii(toy(), operator_style='labels', borders=True)
    assert '[XOR]' in text and '<' in text and 'v' in text


def test_partial_word_projection_is_explicitly_rejected():
    ir = toy()
    ir['nodes'][0]['operands'][0]['positions'] = [0, 2, 1, 3]
    with pytest.raises(ValueError, match='Noncontiguous'):
        to_word_ascii(ir)


@pytest.mark.parametrize('kwargs', [{'column_spacing': 1}, {'alignment': 'center'}, {'word_bits': -1}, {'word_bits': 0}, {'word_bits': False}])
def test_invalid_options_are_rejected(kwargs):
    with pytest.raises(ValueError):
        to_word_ascii(toy(), **kwargs)


def test_public_default_and_explicit_audit_modes():
    from claasp.diagrams import to_ascii, to_audit_ascii, from_ascii
    ir = toy()
    assert to_ascii(ir) == to_word_ascii(ir)
    assert from_ascii(to_audit_ascii(ir)) == ir
    assert to_ascii(ir, format='audit') == to_audit_ascii(ir)


def test_native_roles_and_explicit_override():
    from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    cipher = SpeckBlockCipher(number_of_rounds=1)
    assert [i['role'] for i in from_cipher(cipher)['inputs']] == ['data', 'key']
    assert all(i['role'] == 'unspecified' for i in from_cipher(cipher, roles={})['inputs'])
    arbitrary = Cipher('key_named', 'permutation', ['key'], [4], 4)
    arbitrary.add_round()
    arbitrary.add_cipher_output_component(['key'], [list(range(4))], 4)
    assert from_cipher(arbitrary)['inputs'][0]['role'] == 'unspecified'


def test_permuted_and_repeated_outputs_have_declared_anchors():
    from claasp.diagrams import to_ascii
    for identities in (['right', 'left'], ['left', 'left']):
        cipher = Cipher('generic_order', 'permutation', ['left', 'right'], [4, 4], 8)
        cipher.add_round()
        cipher.add_cipher_output_component(identities, [list(range(4))]*2, 8)
        text = to_ascii(from_cipher(cipher), word_bits=4)
        anchor = next(line for line in text.splitlines() if 'out[0]' in line)
        assert anchor.index('out[0]') < anchor.index('out[1]')
        assert text.count('out[0]') == 1 and text.count('out[1]') == 1


def test_noncommutative_operands_remain_numbered():
    cipher = Cipher('generic_sub', 'permutation', ['a', 'b'], [4, 4], 4)
    cipher.add_round()
    node = cipher.add_modsub_component(['a', 'b'], [list(range(4))]*2, 4)
    cipher.add_cipher_output_component([node.id], [list(range(4))], 4)
    text = to_word_ascii(from_cipher(cipher))
    assert '1v' in text and '<2' in text


def test_full_native_speck_schedule_is_present_and_one_round_has_no_expansion():
    from claasp.diagrams import to_ascii
    from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    one = to_ascii(from_cipher(SpeckBlockCipher(number_of_rounds=1)))
    five = to_ascii(from_cipher(SpeckBlockCipher(number_of_rounds=5)))
    assert one.splitlines()[1].count('S:key[') == 1
    assert 'Declared inputs unused in this computation: key[0], key[1], key[2]' in one
    assert 'round 0: round_key_output = key[3]' in one
    assert five.splitlines()[1].count('S:key[') == 4
    assert all(f'r{r} ' in five for r in range(5))
    assert all(f'round {r}: round_key_output = xor_{r}_5[0]' in five for r in range(1,5))
    assert five.count('>>>7') == 9 and five.count('<<<2') == 9


def test_generic_feistel_f_chain_and_exchange_with_independent_oracle():
    from claasp.diagrams import to_ascii
    cipher = Cipher('generic_feistel', 'permutation', ['left', 'right'], [4,4], 8)
    cipher.add_round()
    rotate = cipher.add_rotate_component(['right'], [list(range(4))], 4, 1)
    invert = cipher.add_not_component([rotate.id], [list(range(4))], 4)
    mix = cipher.add_xor_component(['left', invert.id], [list(range(4))]*2, 4)
    cipher.add_cipher_output_component(['right', mix.id], [list(range(4))]*2, 8)
    text = to_ascii(from_cipher(cipher))
    assert '>>>1' in text and '~' in text and '^' in text and 'x' in text
    for left in range(16):
        for right in range(16):
            rotate_right = (right >> 1) | ((right & 1) << 3)
            expected = (right << 4) | (left ^ (rotate_right ^ 15))
            assert cipher.evaluate([left, right]) == expected


@pytest.mark.parametrize('options', [{'max_calls':1}, {'max_cells':1}, {'max_grid_area':1}, {'max_text_bytes':1}, {'format':'bad'}, {'strategy':'direct-bus'}, {'borders':1}])
def test_public_human_bounds_and_options_fail_explicitly(options):
    from claasp.diagrams import to_ascii
    with pytest.raises(ValueError):
        to_ascii(toy(), **options)


def test_supported_package_and_compatibility_exports_are_identical():
    import claasp.diagrams as compatibility
    import claasp.cipher_modules.diagram as package
    assert compatibility.to_ascii is package.to_ascii
    assert compatibility.to_audit_ascii is package.to_audit_ascii
