"""Validation phase order and independent ownership of parsed glyph results."""
import copy

import pytest

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.diagrams import from_cipher, to_ascii
from claasp.cipher_modules.diagram.word_visual import parse


def _rows(*rows):
    return '\n'.join(rows) + '\n'


@pytest.mark.parametrize('text,message', [
    ('', 'Visual diagram requires complete five-line rows'),
    ('invalid\n', 'Visual diagram requires complete five-line rows'),
    (_rows('     |     ', '           ', '  _______  ', '           ', '     |     '),
     'Invalid visual endpoint'),
    (_rows('     |     ', '     |     ', '-----+     ', '     |     ', '     |     '),
     'Ambiguous three-way plus; a true branch requires o'),
    (_rows('     |     ', '           ', '     |     ', '           ', '           '),
     'Dangling visual wire'),
    (_rows('  _______  ', ' |       | ', ' |  xG   | ', ' |_______| ', '     |     '),
     'Invalid visible inline constant literal'),
    (_rows('  _______  ', ' |       | ', ' |  x01  | ', ' |_______| ', '     |     '),
     "Disconnected visual connector at ((0, 0), 'bottom')"),
])
def test_first_rejection_preserves_validation_phase_and_message(text, message):
    with pytest.raises(ValueError) as failure:
        parse(text)
    assert str(failure.value) == message


def test_complete_pixel_validation_precedes_invalid_literal_and_disconnected_route():
    # A bad interior pixel wins over both an invalid literal and a dangling port.
    text = _rows('  _______  ', ' |?      | ', ' |  xG   | ', ' |_______| ', '     |     ')
    with pytest.raises(ValueError) as failure:
        parse(text)
    assert str(failure.value) == 'Broken or directionally invalid complete glyph at (0, 0)'


def test_operation_output_validation_precedes_neighbour_checks():
    text = _rows('  _______  ', ' |       | ', ' |  NOT  | ', ' |_______| ', '           ')
    with pytest.raises(ValueError) as failure:
        parse(text)
    assert str(failure.value) == 'Operation requires its directed output connector'


def test_each_parse_owns_its_cells_sources_and_port_sets():
    text = to_ascii(from_cipher(SpeckBlockCipher(number_of_rounds=1)))
    first = parse(text)
    frozen = copy.deepcopy(first)
    second = parse(text)
    assert first == second
    key = next(iter(second['cells']))
    second['cells'][key]['ports'].clear()
    second['cells'].clear()
    second['sources'].clear()
    assert first == frozen
    assert parse(text) == frozen
