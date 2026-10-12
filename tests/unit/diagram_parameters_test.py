import copy
import json
import pytest
from claasp.cipher import Cipher
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher
from claasp.cipher_modules.diagram.manual_blocks import MARKER
from claasp.cipher_modules.diagram import parameters


def constant_ir(value=0x8000000000000001, bits=64):
    c = Cipher('anonymous_parameters', 'permutation', ['a'], [bits], bits)
    c.add_round()
    k = c.add_constant_component(bits, value)
    x = c.add_xor_component(['a', k.id], [list(range(bits))]*2, bits)
    c.add_cipher_output_component([x.id], [list(range(bits))], bits)
    return from_cipher(c)


def test_opt_in_visible_literal_exact_cycles_and_independent_values():
    ir = constant_ir()
    with pytest.raises(ValueError, match='label capacity'):
        to_ascii(ir, annotations=True, word_bits=64)
    text = to_ascii(ir, annotations=True, word_bits=64, parameter_refs=True)
    assert 'CONST' in text and 'P0 CONST bits=64 literal=0x8000000000000001' in text
    for _ in range(3):
        actual = from_ascii(text)
        assert actual == ir
        assert to_ascii(actual, annotations=True, word_bits=64, parameter_refs=True) == text
    cipher = to_cipher(actual)
    for value in [0, 1, 7, (1 << 64)-1]:
        assert cipher.evaluate([value]) == value ^ 0x8000000000000001


def test_visible_and_local_parameters_cannot_disagree():
    text = to_ascii(constant_ir(), annotations=True, word_bits=64, parameter_refs=True)
    body, footer = text.split(MARKER)
    for mutated in [body.replace('literal=0x8000000000000001', 'literal=0x8000000000000000'),
                    body.replace('bits=64 literal=', 'bits=63 literal='),
                    body.replace('P0 CONST', 'P1 CONST'),
                    body.replace('P0 CONST', 'P00 CONST'),
                    body.replace(parameters.END, '\nP1 CONST bits=64 literal=0x1'+parameters.END),
                    body.replace(parameters.END, '\nP0 CONST bits=64 literal=0x8000000000000001'+parameters.END),
                    body.replace(parameters.END, ''),
                    body.replace('CONST', 'XOR', 1),
                    body.replace('  P0   ', '  P1   ', 1)]:
        assert mutated != body
        with pytest.raises(ValueError):
            from_ascii(mutated + MARKER + footer)
    metadata = json.loads(footer)
    definition = next(item['definition'] for item in metadata['records'] if 'parameter_ref' in item['definition'])
    definition['description'][0] = '0x8000000000000000'
    with pytest.raises(ValueError):
        from_ascii(body + MARKER + json.dumps(metadata))


def test_explicit_modulus_keeps_native_description_and_arithmetic():
    c = Cipher('anonymous_modulus', 'permutation', ['a', 'b'], [32, 32], 32)
    c.add_round()
    x = c.add_modadd_component(['a', 'b'], [list(range(32))]*2, 32, 1 << 32)
    c.add_cipher_output_component([x.id], [list(range(32))], 32)
    ir = from_cipher(c)
    text = to_ascii(ir, annotations=True, word_bits=32, parameter_refs=True)
    assert 'P0 MODADD bits=32 modulus=4294967296' in text
    assert from_ascii(text) == ir
    restored = to_cipher(from_ascii(text))
    for values in [[0, 0], [(1 << 32)-1, 1], [(1 << 32)-1]*2]:
        assert restored.evaluate(values) == sum(values) & ((1 << 32)-1)
    with pytest.raises(ValueError):
        from_ascii(text.replace('modulus=4294967296', 'modulus=65536'))


def test_parameter_deduplication_is_exact_typed_and_source_free():
    ir = constant_ir()
    node = copy.deepcopy(ir['nodes'][0]); node['id'] = 'other_constant'
    ir['nodes'].insert(1, node)
    refs = parameters.assignments(ir)
    assert refs[0] == refs[1] == 'P0'
    node['bits'] = 128
    assert parameters.assignments(ir)[0] != parameters.assignments(ir)[1]
    definitions = [dict(ir['nodes'][index], parameter_ref=tag) for index, tag in parameters.assignments(ir).items()]
    legend = parameters.serialize(definitions)
    assert 'other_constant' not in legend and 'operands' not in legend


def test_128_bit_last_bit_and_renaming_invariance():
    ir = constant_ir((1 << 127) | 17, 128)
    text = to_ascii(ir, annotations=True, word_bits=128, parameter_refs=True)
    assert from_ascii(text) == ir
    assert to_cipher(from_ascii(text)).evaluate([0]) == (1 << 127) | 17
    renamed = copy.deepcopy(ir)
    renamed['name'] = 'different_name'
    renamed['inputs'][0]['id'] = 'renamed_input'
    names = {node['id']: 'renamed_'+str(index) for index, node in enumerate(ir['nodes'])}
    names['a'] = 'renamed_input'
    for node in renamed['nodes']:
        node['id'] = names[node['id']]
        for edge in node['operands']:
            edge['source'] = names[edge['source']]
    other = to_ascii(renamed, annotations=True, word_bits=128, parameter_refs=True)
    assert other.split(MARKER)[0] == text.split(MARKER)[0]


def test_parameter_option_is_explicit_and_audit_rejects_it():
    with pytest.raises(ValueError):
        to_ascii(constant_ir(), annotations=True, parameter_refs=1)
    with pytest.raises(ValueError, match='audit'):
        to_ascii(constant_ir(), format='audit', parameter_refs=True)


def test_literal_base_and_leading_zero_spelling_are_preserved():
    for spelling in ['0X08000000000000001', '0b1' + '0'*62 + '1']:
        ir = constant_ir()
        ir['nodes'][0]['description'][0] = spelling
        text = to_ascii(ir, annotations=True, word_bits=64, parameter_refs=True)
        assert 'literal='+spelling in text
        assert from_ascii(text) == ir
    with pytest.raises(ValueError, match='exact integer range'):
        parameters.facts({'type': 'word_operation', 'bits': 64,
                          'description': ['MODADD', 2, 1 << 64]})


@pytest.mark.parametrize('operation', ['modadd', 'modsub', 'modmul'])
def test_binary_explicit_modulus_generic_operations(operation):
    c = Cipher('anonymous_' + operation, 'permutation', ['a', 'b'], [8, 8], 8)
    c.add_round()
    x = getattr(c, 'add_' + operation + '_component')(['a', 'b'], [list(range(8))]*2, 8, 251)
    c.add_cipher_output_component([x.id], [list(range(8))], 8)
    ir = from_cipher(c)
    text = to_ascii(ir, annotations=True, word_bits=8, parameter_refs=True)
    assert operation.upper()+' bits=8 modulus=251' in text
    assert from_ascii(text) == ir
    restored = to_cipher(from_ascii(text))
    for a, b in [(0, 0), (255, 1), (7, 19), (255, 255)]:
        expected = {'modadd': a+b, 'modsub': a-b, 'modmul': a*b}[operation] % 251
        assert restored.evaluate([a, b]) == expected
