"""Evaluation evidence for the fixed-length Trivium keystream function.

Two independent oracles are used.  ``_reference_trivium`` below is a direct
array transcription of the published Trivium pseudocode, written independently
of the typed graph and of legacy CLAASP, and is the oracle for arbitrary
reduced parameters.  The fixed vectors are the published eSTREAM 80/80 test
vectors, which pin the boundary bit order that a self-consistent reference
cannot establish on its own.
"""

import pytest

from claasp.components import BitwiseAnd, Constant, Xor
from claasp.encoding import units_from_int
from claasp.primitives import Trivium
from claasp.primitives.block_functions.trivium import estream_bytes_to_bit_sequence
from claasp.representations.execution import BatchEvaluator

#: eSTREAM/ECRYPT ``Trivium`` 80-bit key, 80-bit IV test vectors, quoted as
#: published byte strings: ``(set, vector, key, iv, stream[0..15])``.
ESTREAM_VECTORS = (
    (1, 0, 0x80000000000000000000, 0, 0x38EB86FF730D7A9CAF8DF13A4420540D),
    (1, 9, 0x00400000000000000000, 0, 0x61208D286BC1DC431171EDA5CAF79D95),
    (1, 18, 0x00002000000000000000, 0, 0xC8F9031DABF8DB03FF120D05512B5F24),
    (2, 0, 0x00000000000000000000, 0, 0xFBE0BF265859051B517A2E4E239FC97F),
    (2, 9, 0x09090909090909090909, 0, 0xAB97616E7BAF0921F424B2573BFA15BD),
)

#: Legacy CLAASP ``TriviumStreamCipher`` doctest and
#: ``tests/unit/ciphers/stream_ciphers/trivium_stream_cipher_test.py`` value.
#: Unlike the skipped Gurobi fixtures it is executed by the legacy suite, so it
#: is an independent oracle produced by an unrelated implementation.
LEGACY_ALL_ZERO_KEYSTREAM = 0xDF07FD641A9AA0D88A5E7472C4F993FE6A4CC06898E0F3B4E7159EF0854D97B3


def _reference_trivium(key_bits, iv_bits, clocks, keystream_bits):
    """Transcribe the published Trivium pseudocode over ``s[1] .. s[288]``.

    ``key_bits[m]`` and ``iv_bits[m]`` are the eSTREAM bit sequences, loaded at
    ``s(80 - m)`` and ``s(173 - m)``.  Returns ``(keystream_bits, state)``.
    """

    s = [0] * 289
    for index in range(80):
        s[80 - index] = key_bits[index]
        s[173 - index] = iv_bits[index]
    s[286] = s[287] = s[288] = 1
    keystream = []
    for clock in range(clocks + keystream_bits):
        t1 = s[66] ^ s[93]
        t2 = s[162] ^ s[177]
        t3 = s[243] ^ s[288]
        if clock >= clocks:
            keystream.append(t1 ^ t2 ^ t3)
        feedback_a = t3 ^ (s[286] & s[287]) ^ s[69]
        feedback_b = t1 ^ (s[91] & s[92]) ^ s[171]
        feedback_c = t2 ^ (s[175] & s[176]) ^ s[264]
        s[1:94] = [feedback_a] + s[1:93]
        s[94:178] = [feedback_b] + s[94:177]
        s[178:289] = [feedback_c] + s[178:288]
    return keystream, s[1:289]


def _pack(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _unpack(value, width):
    return [(value >> (width - 1 - index)) & 1 for index in range(width)]


@pytest.fixture(scope="module")
def standard_trivium():
    return Trivium(keystream_bit_size=128)


@pytest.mark.parametrize(
    "vector_set, vector, key, iv, stream",
    ESTREAM_VECTORS,
    ids=[f"set{entry[0]}_vector{entry[1]}" for entry in ESTREAM_VECTORS],
)
def test_published_estream_vectors(standard_trivium, vector_set, vector, key, iv, stream):
    keystream = standard_trivium.evaluate(
        key=estream_bytes_to_bit_sequence(key, 10),
        iv=estream_bytes_to_bit_sequence(iv, 10),
    )

    assert estream_bytes_to_bit_sequence(keystream, 16) == stream


def test_legacy_all_zero_keystream_is_reproduced():
    primitive = Trivium(keystream_bit_size=256)

    assert primitive.evaluate(key=0, iv=0) == LEGACY_ALL_ZERO_KEYSTREAM


@pytest.mark.parametrize("clocks, keystream_bits", ((0, 4), (13, 1), (66, 8), (200, 16)))
@pytest.mark.parametrize(
    "key, iv",
    (
        (0, 0),
        (1 << 79, 0),
        (0, 1 << 79),
        (0x0123456789ABCDEF0123, 0xFEDCBA98765432100FED),
    ),
)
def test_reduced_keystream_matches_the_independent_reference(clocks, keystream_bits, key, iv):
    primitive = Trivium(number_of_initialization_clocks=clocks, keystream_bit_size=keystream_bits)
    expected, _ = _reference_trivium(_unpack(key, 80), _unpack(iv, 80), clocks, keystream_bits)

    assert primitive.evaluate(key=key, iv=iv) == _pack(expected)


@pytest.mark.parametrize("clocks", (0, 1, 13, 200))
def test_state_output_matches_the_independent_reference(clocks):
    key, iv = 0x0123456789ABCDEF0123, 0xFEDCBA98765432100FED
    primitive = Trivium(number_of_initialization_clocks=clocks, keystream_bit_size=0)
    _, expected = _reference_trivium(_unpack(key, 80), _unpack(iv, 80), clocks, 0)

    assert primitive.graph.output.array_type.encoded_bit_size == 288
    assert primitive.evaluate(key=key, iv=iv) == _pack(expected)


def test_scalar_and_batch_evaluation_agree():
    primitive = Trivium(number_of_initialization_clocks=200, keystream_bit_size=8)
    keys = (0x0123456789ABCDEF0123, 0)
    ivs = (0xFEDCBA98765432100FED, 1 << 79)

    batch = BatchEvaluator().evaluate(
        primitive,
        {
            "key": tuple(units_from_int(key, 1, 80) for key in keys),
            "iv": tuple(units_from_int(iv, 1, 80) for iv in ivs),
        },
    )

    assert batch.outputs == tuple(
        units_from_int(primitive.evaluate(key=key, iv=iv), 1, 8) for key, iv in zip(keys, ivs)
    )


def test_graph_shape_and_reused_components():
    primitive = Trivium(number_of_initialization_clocks=13, keystream_bit_size=1)

    assert primitive.family_name == "trivium"
    assert primitive.graph.input_ports["key"].array_type.unit_count == 80
    assert primitive.graph.input_ports["iv"].array_type.unit_count == 80
    assert primitive.graph.output.array_type.encoded_bit_size == 1
    assert len(primitive.graph.rounds) == 15
    assert {type(component) for component in primitive.graph.components} == {
        Constant,
        Xor,
        BitwiseAnd,
    }
    assert sum(isinstance(component, BitwiseAnd) for component in primitive.graph.components) == 42


def test_estream_conversion_is_an_involution_and_validates_inputs():
    assert estream_bytes_to_bit_sequence(0x8000, 2) == 0x0100
    assert estream_bytes_to_bit_sequence(0x0100, 2) == 0x8000
    with pytest.raises(ValueError, match="does not fit"):
        estream_bytes_to_bit_sequence(0x1FF, 1)
    with pytest.raises(ValueError, match="positive integer"):
        estream_bytes_to_bit_sequence(0, 0)
    with pytest.raises(TypeError, match="must be an integer"):
        estream_bytes_to_bit_sequence(True, 1)


@pytest.mark.parametrize(
    "clocks, keystream_bits, message",
    (
        (-1, 1, "must not be negative"),
        (1, -1, "must not be negative"),
    ),
)
def test_invalid_parameters_are_rejected(clocks, keystream_bits, message):
    with pytest.raises(ValueError, match=message):
        Trivium(number_of_initialization_clocks=clocks, keystream_bit_size=keystream_bits)


@pytest.mark.parametrize("clocks, keystream_bits", ((True, 1), (1.0, 1), (1, True)))
def test_non_integer_parameters_are_rejected(clocks, keystream_bits):
    with pytest.raises(TypeError, match="must be an integer"):
        Trivium(number_of_initialization_clocks=clocks, keystream_bit_size=keystream_bits)
