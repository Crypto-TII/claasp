from io import BytesIO

import pytest

from claasp_next.analysis.statistical_datasets import (
    cbc_dataset,
    correlation_dataset,
    high_density_dataset,
    low_density_dataset,
)
from claasp_next.primitives import Speck


@pytest.fixture
def speck():
    return Speck(number_of_rounds=1)


def test_correlation_dataset_is_lazy_reiterable_and_has_fixed_evidence(speck):
    dataset = correlation_dataset(speck, "plaintext", 2, 3, seed=5, fixed_inputs={"key": 0})
    first = tuple(dataset)

    assert first == tuple(dataset)
    assert [(item.sample, item.block) for item in first] == [
        (0, 0),
        (0, 1),
        (0, 2),
        (1, 0),
        (1, 1),
        (1, 2),
    ]
    assert tuple(item.value for item in first) == (
        4143310035,
        3789494373,
        837897962,
        4143310035,
        3789494373,
        837897962,
    )


def test_cbc_dataset_chains_outputs_and_serializes_lazily(speck):
    dataset = cbc_dataset(speck, "plaintext", 1, 3, seed=7, fixed_inputs={"key": 0})
    records = tuple(dataset)

    assert tuple(item.value for item in records) == (0, 0, 0)
    assert tuple(dataset.iter_bytes()) == (b"\x00\x00\x00\x00",) * 3

    stream = BytesIO()
    assert dataset.write_binary(stream) == 12
    assert stream.getvalue() == b"\x00" * 12

    manifest = dataset.manifest()
    assert manifest.primitive == "speck"
    assert manifest.realization == "default"
    assert manifest.execution_engine == "python_scalar"
    assert manifest.schema_version == 2
    assert manifest.record_count == 3
    assert manifest.byte_count == 12
    assert manifest.sha256 == "15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b"
    assert manifest.to_json().endswith("\n")
    assert '"byte_order":"big"' in manifest.to_json()
    assert '"bit_order":"msb_first"' in manifest.to_json()


def test_manifest_binds_construction_and_realization_provenance():
    from claasp_next.primitives import AES

    dataset = cbc_dataset(
        AES(number_of_rounds=1, realization="algebraic"),
        "plaintext",
        1,
        1,
        fixed_inputs={"key": 0},
    )
    manifest = dataset.manifest()

    assert manifest.primitive == "aes"
    assert manifest.realization == "algebraic"
    assert manifest.execution_engine == "python_scalar"
    assert manifest.serialization == "raw_fixed_width_outputs_v1"
    assert manifest.record_order == "sample_major_then_block"
    assert manifest.fixed_inputs == (("key", 0),)


def test_density_families_have_exact_weights_and_are_complements(speck):
    low = low_density_dataset(speck, "plaintext", 1, ratio=0, seed=3, fixed_inputs={"key": 0})
    high = high_density_dataset(speck, "plaintext", 1, ratio=0, seed=3, fixed_inputs={"key": 0})

    assert low.block_count == high.block_count == 33
    assert len(tuple(low)) == len(tuple(high)) == 33
    assert tuple(low.iter_selected_inputs())[:3] == (0, 1 << 31, 1 << 30)
    assert tuple(high.iter_selected_inputs())[:3] == (0xFFFFFFFF, 0x7FFFFFFF, 0xBFFFFFFF)


def test_density_weight_two_sampling_and_validation(speck):
    dataset = low_density_dataset(speck, "plaintext", 2, ratio=0.01, seed=11)
    assert dataset.block_count == 38
    assert len(tuple(dataset)) == 76

    with pytest.raises(ValueError, match="between zero and one"):
        low_density_dataset(speck, "plaintext", 1, ratio=1.1)
    with pytest.raises(ValueError, match="widths to match"):
        cbc_dataset(speck, "key", 1, 1)
    with pytest.raises(ValueError, match="selected or unknown"):
        correlation_dataset(speck, "plaintext", 1, 1, fixed_inputs={"plaintext": 0})
