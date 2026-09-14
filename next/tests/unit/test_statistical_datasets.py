from random import getstate

import pytest

from claasp_next.analysis.datasets import generate_avalanche_dataset, generate_random_dataset
from claasp_next.primitives import Speck


def test_random_dataset_is_reproducible_and_preserves_global_rng():
    primitive = Speck(number_of_rounds=1)
    state = getstate()
    first = generate_random_dataset(primitive, 3, seed=17)
    second = generate_random_dataset(primitive, 3, seed=17)

    assert first == second
    assert getstate() == state
    assert tuple(sample.input("plaintext") for sample in first.samples) == (
        2241903809,
        1303193990,
        1243931546,
    )
    assert all(sample.output == primitive.evaluate(dict(sample.inputs)) for sample in first.samples)


def test_random_dataset_can_fix_an_input_and_validates_arguments():
    primitive = Speck(number_of_rounds=1)
    dataset = generate_random_dataset(primitive, 2, seed=4, fixed_inputs={"key": 0})
    assert [sample.input("key") for sample in dataset.samples] == [0, 0]

    with pytest.raises(ValueError, match="positive"):
        generate_random_dataset(primitive, 0)
    with pytest.raises(ValueError, match="unknown fixed"):
        generate_random_dataset(primitive, 1, fixed_inputs={"nonce": 0})


def test_avalanche_dataset_records_every_msb_first_input_flip():
    primitive = Speck(number_of_rounds=1)
    dataset = generate_avalanche_dataset(
        primitive, "plaintext", 2, seed=9, fixed_inputs={"key": 0}
    )

    assert dataset.input_bit_count == dataset.output_bit_count == 32
    assert dataset.sample_count == 2
    assert len(dataset.records) == 64
    assert dataset.records[0].input_bit == 0
    assert dataset.records[0].output_difference == 0x03000300
