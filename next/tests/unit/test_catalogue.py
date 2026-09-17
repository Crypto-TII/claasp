from dataclasses import FrozenInstanceError

import pytest

from claasp_next.catalogue import Catalogue, PrimitiveRecord, catalogue


def test_catalogue_returns_sorted_immutable_records():
    records = catalogue.primitives()
    assert len(records) == 145
    assert isinstance(records, tuple)
    assert records == tuple(sorted(records, key=lambda item: (item.category, item.name)))
    assert isinstance(records[0], PrimitiveRecord)
    with pytest.raises(FrozenInstanceError):
        records[0].name = "changed"


def test_primitive_lookup_preserves_classification_and_typed_contract():
    aes = Catalogue().primitive("AES")
    assert aes.official_name == "AES"
    assert aes.qualified_name == "claasp_next.primitives.block_ciphers.aes.AES"
    assert aes.category == "block_ciphers"
    assert aes.kind == "block_cipher"
    assert aes.classified_input_roles == ("key", "plaintext")
    assert tuple(item.name for item in aes.inputs) == ("plaintext", "key")
    assert aes.bijectivity_obligation
    assert aes.fixed_evidence


@pytest.mark.parametrize(
    ("filter_name", "included", "excluded"),
    (
        ("arx", "Speck", "Zuc"),
        ("pure-arx", "ChaCha", "Speck"),
        ("andrx", "Simon", "AES"),
        ("sbox-based", "AES", "Speck"),
        ("fsr-based", "A51", "AES"),
        ("tweakable_block_cipher", "Mantis", "AES"),
    ),
)
def test_design_filters_preserve_legacy_discovery_intent(filter_name, included, excluded):
    names = {item.name for item in catalogue.primitives(filters=filter_name)}
    assert included in names
    assert excluded not in names


def test_category_and_component_filters_compose():
    records = catalogue.primitives(category="block_cipher", components=("sbox", "xor"))
    assert records
    assert all(item.category == "block_ciphers" for item in records)
    assert all(item.components & {"BitVectorSBox", "SBox"} for item in records)
    assert all("Xor" in item.components for item in records)


def test_pure_andrx_filter_does_not_promote_constant_bearing_graphs():
    assert catalogue.primitives(filters="pure-andrx") == ()


def test_component_records_are_one_to_one_with_teaching_wrappers():
    components = catalogue.components()
    assert len(components) == 26
    assert {item.name for item in catalogue.components(names=("SBox", "LinearMap"))} == {
        "SBox", "LinearMap",
    }


def test_unknown_primitive_has_clear_error():
    with pytest.raises(KeyError, match="unknown primitive 'Missing'"):
        catalogue.primitive("Missing")
