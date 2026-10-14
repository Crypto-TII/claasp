"""Binding validation stage order and ownership of ordinary trace results."""
import copy

import pytest

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.diagrams import from_cipher
from claasp.cipher_modules.diagram.word_bindings import export_bindings, trace_bindings


def _ordinary_bindings():
    return export_bindings(from_cipher(SpeckBlockCipher(number_of_rounds=1)))


@pytest.mark.parametrize('case,message', [
    ('schema', 'Unsupported experimental word binding schema'),
    ('fields', 'Unexpected or missing binding metadata field'),
    ('operation_fields', 'Unexpected operation metadata field; source links are forbidden'),
    ('header', 'Unexpected native header metadata field'),
    ('body', 'Visual diagram requires complete five-line rows'),
    ('coordinates', 'Input bindings disagree with actual visible endpoints'),
    ('capacity', 'Word width exceeds actual input fragment cardinality'),
    ('rounds', 'Declared rounds exceed explicit native record capacity'),
])
def test_contradictions_preserve_the_first_validation_error(case, message):
    body, metadata = _ordinary_bindings()
    if case in ('schema', 'fields', 'operation_fields', 'header', 'body'):
        body = 'invalid\n'
    if case == 'schema':
        metadata['schema'] = 'unknown'
    elif case == 'fields':
        metadata.pop('header')
    elif case == 'operation_fields':
        metadata['operations'][0]['source'] = 'forbidden'
    elif case == 'header':
        metadata['header']['extra'] = True
    elif case == 'body':
        metadata['inputs'][0]['binding']['positions'].pop()
    elif case == 'coordinates':
        metadata['inputs'][0]['at'][0] += 1
        metadata['inputs'][0]['binding']['positions'].pop()
    else:
        metadata['operations'][0]['definition']['type'] = 'unsupported'
        if case == 'capacity':
            metadata['inputs'][0]['binding']['positions'].pop()
        else:
            metadata['header']['rounds'] = 0
    with pytest.raises(ValueError) as failure:
        trace_bindings(body, metadata)
    assert str(failure.value) == message


def test_ordinary_trace_preserves_input_metadata_and_ordered_sources():
    body, metadata = _ordinary_bindings()
    frozen = copy.deepcopy(metadata)
    first = trace_bindings(body, metadata)
    second = trace_bindings(body, metadata)
    assert metadata == frozen
    assert first == second
    assert first['exact_native_reconstruction'] is False
    assert first['operation_sources']
    second['operation_sources'].clear()
    assert first['operation_sources']
