from random import Random

import pytest

from claasp_next.analysis.neural import (
    component_output_dataset,
    round_component_ids,
    xor_differential_component_dataset,
)
from claasp_next.primitives import Speck
from claasp_next.encoding import bits_from_int, int_from_bits


def test_round_component_ids_matches_the_primitive_graph_round_structure():
    primitive = Speck(number_of_rounds=2)

    round_0 = round_component_ids(primitive, 0)
    round_1 = round_component_ids(primitive, 1)

    assert round_0 == tuple(component.component_id for component in primitive.rounds[0].components)
    assert round_1 == tuple(component.component_id for component in primitive.rounds[1].components)
    # Semantic references stay stable even when automatic identifiers change.
    assert primitive.round_states[0][1].owner_id in round_0
    assert primitive.key_schedule_states[0][1].owner_id in round_0
    assert {
        owner_id for owner_id, _ in primitive.selection_bit_sources(primitive.output)
    } <= set(round_1)

    with pytest.raises(ValueError, match="range"):
        round_component_ids(primitive, 2)
    with pytest.raises(ValueError, match="range"):
        round_component_ids(primitive, -1)


def test_component_output_dataset_matches_direct_trace_inspection_of_round_state():
    """Cross-check the projected feature bits against a direct trace lookup.

    This targets the right word of round zero -- one of the two components that
    jointly hold Speck's state -- exactly like legacy's
    ``round_output`` projection in ``claasp/cipher_modules/neural_network_tests.py``,
    but through the typed ``ExecutionTrace`` instead of a description-string
    match.
    """

    primitive = Speck(number_of_rounds=2)
    component_id = primitive.round_states[0][1].owner_id
    seed = 5
    samples = 16
    dataset = component_output_dataset(
        primitive, "plaintext", component_id, samples=samples, seed=seed
    )

    plaintext_width = primitive.input("plaintext").value_type.encoded_bit_size
    key_width = primitive.input("key").value_type.encoded_bit_size
    component_width = primitive.port(component_id).value_type.encoded_bit_size
    assert dataset.feature_width == plaintext_width + component_width

    # Replay the dataset's own seeded random stream so the "real" (label 1)
    # rows can be pinned to a concrete plaintext/key pair, independently of
    # the generator's internals: the generator draws one width-sized number
    # per declared input as its held-fixed baseline (plaintext's draw is
    # discarded once the varied input is overwritten per sample) before
    # entering the per-sample loop.
    random = Random(seed)
    random.getrandbits(plaintext_width)
    fixed_key = random.getrandbits(key_width)

    verified_real_rows = 0
    for row, label in zip(dataset.features, dataset.labels):
        assert random.getrandbits(1) == label
        varied_value = random.getrandbits(plaintext_width)
        assert int_from_bits(row[:plaintext_width]) == varied_value
        if label:
            trace = primitive.evaluate_with_trace(
                {"plaintext": varied_value, "key": fixed_key}
            ).trace
            expected_word = trace.value_of(component_id)[0]
            assert row[plaintext_width:] == bits_from_int(expected_word, component_width)
            verified_real_rows += 1
        else:
            for _ in range(component_width):
                random.getrandbits(1)

    assert verified_real_rows > 0


def test_component_output_dataset_supports_concatenated_round_projection():
    primitive = Speck(number_of_rounds=2)
    ids = round_component_ids(primitive, 1)
    dataset = component_output_dataset(primitive, "key", ids, samples=6, seed=2)

    expected_width = sum(
        primitive.port(component_id).value_type.encoded_bit_size for component_id in ids
    )
    key_width = primitive.input("key").value_type.encoded_bit_size
    assert dataset.feature_width == key_width + expected_width
    assert dataset.feature_names[0] == "key[0]"
    assert dataset.feature_names[-1] == f"{'+'.join(ids)}[{expected_width - 1}]"


def test_xor_differential_component_dataset_matches_direct_trace_inspection():
    primitive = Speck(number_of_rounds=2)
    component_id = primitive.key_schedule_states[0][1].owner_id
    differences = {"plaintext": 0x0040_0000, "key": 0}
    seed = 11
    samples = 10
    dataset = xor_differential_component_dataset(
        primitive, differences, component_id, samples=samples, seed=seed
    )

    plaintext_width = primitive.input("plaintext").value_type.encoded_bit_size
    key_width = primitive.input("key").value_type.encoded_bit_size
    component_width = primitive.port(component_id).value_type.encoded_bit_size
    assert dataset.feature_width == 2 * component_width

    random = Random(seed)
    verified_real_rows = 0
    for row, label in zip(dataset.features, dataset.labels):
        assert random.getrandbits(1) == label
        first_plaintext = random.getrandbits(plaintext_width)
        first_key = random.getrandbits(key_width)
        if label:
            second_plaintext = first_plaintext ^ differences["plaintext"]
            second_key = first_key ^ differences["key"]
            first_trace = primitive.evaluate_with_trace(
                {"plaintext": first_plaintext, "key": first_key}
            ).trace
            second_trace = primitive.evaluate_with_trace(
                {"plaintext": second_plaintext, "key": second_key}
            ).trace
            expected_first = bits_from_int(
                first_trace.value_of(component_id)[0], component_width
            )
            expected_second = bits_from_int(
                second_trace.value_of(component_id)[0], component_width
            )
            assert row == expected_first + expected_second
            verified_real_rows += 1
        else:
            random.getrandbits(plaintext_width)
            random.getrandbits(key_width)

    assert verified_real_rows > 0


def test_component_output_dataset_validates_component_ids():
    primitive = Speck(number_of_rounds=1)

    with pytest.raises(ValueError, match="must not be empty"):
        component_output_dataset(primitive, "plaintext", (), samples=2)
    with pytest.raises(KeyError):
        component_output_dataset(primitive, "plaintext", "not_a_component", samples=2)
