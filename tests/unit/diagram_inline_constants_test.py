"""Established two-line constant glyphs, read through their actual routes."""
import copy
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import Diagrams, from_ascii, to_ascii, to_cipher
from claasp.cipher_modules.diagram import manual_blocks, word_visual
from claasp.ciphers.permutations.alzette_permutation import AlzettePermutation
from claasp.ciphers.permutations.gimli_permutation import GimliPermutation


def integer_alzette(value):
    mask = (1 << 32)-1
    x, y = value >> 32, value & mask
    def right(word, amount):
        return ((word >> amount) | (word << (32-amount))) & mask
    for ry, rx in ((31, 24), (17, 17), (0, 31), (24, 16)):
        x = (x+right(y, ry)) & mask
        y ^= right(x, rx)
        x ^= 0xB7E15162
    return (x << 32) | y


def integer_gimli_first_round(value):
    mask = (1 << 32)-1
    words = [(value >> (32*(11-i))) & mask for i in range(12)]
    result = [0]*12
    def left(word, amount):
        return ((word << amount) | (word >> (32-amount))) & mask
    for col in range(4):
        x, y, z = left(words[col], 24), left(words[4+col], 9), words[8+col]
        result[col] = (z ^ y ^ ((x & y) << 3)) & mask
        result[4+col] = (y ^ x ^ ((x | z) << 1)) & mask
        result[8+col] = (x ^ (z << 1) ^ ((y & z) << 2)) & mask
    result[0], result[1] = result[1], result[0]
    result[2], result[3] = result[3], result[2]
    result[0] ^= 0x9E377918
    packed = 0
    for word in result:
        packed = (packed << 32) | word
    return packed


def constant_cipher(value, bits):
    cipher = Cipher('inline_literal', 'permutation', ['plaintext'], [bits], bits)
    cipher.add_round()
    constant = cipher.add_constant_component(bits, value)
    operation = cipher.add_xor_component(['plaintext', constant.id], [list(range(bits))]*2, bits)
    cipher.add_cipher_output_component([operation.id], [list(range(bits))], bits)
    return cipher


@pytest.mark.parametrize('digits', range(7, 14))
@pytest.mark.parametrize('routed', [False, True])
def test_each_ordinary_two_line_capacity(digits, routed):
    value = int('A'+'123456789ABCD'[:digits-1], 16)
    bits = 4*digits
    diagram = Diagrams(constant_cipher(value, bits))
    ir = diagram.ir
    model = word_visual.build(ir, routed_words=routed)
    constant = next(cell for cell in model['cells'].values()
                    if cell.get('definition', {}).get('type') == 'constant')
    assert word_visual._art(constant) == manual_blocks.art(constant)
    body = diagram.to_ascii(routed_words=routed)
    parsed = word_visual.parse(body)
    actual = next(cell for cell in parsed['cells'].values() if 'constant_literal' in cell)
    assert actual['constant_literal'] == 'x'+format(value, 'X')
    for sample in (0, (1 << bits)-1, 0x12345):
        result = word_visual.evaluate(body, word_visual.input_words(model, ir, [sample]), bits, model['cipher_columns'])
        assert result['cipher'] == sample ^ value
    for _ in range(3):
        annotated = to_ascii(ir, routed_words=routed, annotations=True)
        assert from_ascii(annotated) == ir
        assert to_ascii(from_ascii(annotated), routed_words=routed) == body
        ir = from_ascii(annotated)
    renamed = copy.deepcopy(ir)
    names = {n['id']: f'renamed_{i}' for i, n in enumerate(renamed['inputs']+renamed['nodes'])}
    for node in renamed['inputs']+renamed['nodes']:
        node['id'] = names[node['id']]
        for edge in node.get('operands', []):
            edge['source'] = names[edge['source']]
    assert to_ascii(renamed, routed_words=routed) == body
    assert diagram.to_tikz(routed_words=routed) == diagram.to_tikz(routed_words=routed)


@pytest.mark.parametrize('factory', [AlzettePermutation, lambda: GimliPermutation(number_of_rounds=1)])
def test_normal_constant_using_permutations(factory):
    cipher = factory()
    diagram = Diagrams(cipher)
    body = diagram.to_ascii(routed_words=True)
    annotated = diagram.to_ascii(routed_words=True, annotations=True)
    assert from_ascii(annotated) == diagram.ir
    restored = to_cipher(from_ascii(annotated))
    model = word_visual.build(diagram.ir, routed_words=True)
    bits = 32
    width = diagram.ir['inputs'][0]['bits']
    for sample in (0, (1 << width)-1, int('12345678'*(width//32), 16)):
        expected = cipher.evaluate([sample])
        independent = integer_alzette if width == 64 else integer_gimli_first_round
        assert expected == independent(sample)
        assert restored.evaluate([sample]) == expected
        assert word_visual.evaluate(body, word_visual.input_words(model, diagram.ir, [sample]),
                                    bits, model['cipher_columns'])['cipher'] == expected
    assert diagram.to_ascii(routed_words=True) == body
    with pytest.raises(ValueError, match='live-operand spill'):
        diagram.to_ascii()


@pytest.mark.parametrize('value', [0, 1, 0x4B, 0x123456])
def test_short_constants_keep_existing_pixels(value):
    model = word_visual.build(Diagrams(constant_cipher(value, 32)).ir, routed_words=True)
    constant = next(cell for cell in model['cells'].values()
                    if cell.get('definition', {}).get('type') == 'constant')
    art = word_visual._art(constant)
    assert art[1] == ' |       | '
    assert art[2][2:9].strip() == 'x'+format(value, '02X')
