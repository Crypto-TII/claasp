"""Contract and equivalence evidence for audited primitive realizations."""

import json
import random
from pathlib import Path

import pytest

from claasp.primitives.block_ciphers.aradi import Aradi
from claasp.primitives.block_ciphers.gift import Gift
from claasp.primitives.block_ciphers.katan import Katan
from claasp.primitives.block_ciphers.ktantan import Ktantan
from claasp.primitives.block_ciphers.simeck import Simeck
from claasp.primitives.block_ciphers.simon import Simon
from claasp.primitives.block_ciphers.tinyjambu import TinyJambu
from claasp.primitives.block_ciphers.ublock import Ublock
from claasp.primitives.permutations.ascon import Ascon
from claasp.primitives.permutations.gaston import Gaston
from claasp.primitives.permutations.gimli import Gimli
from claasp.primitives.permutations.keccak import Keccak
from claasp.primitives.permutations.spongent_pi import SpongentPi
from claasp.primitives.permutations.xoodoo import Xoodoo
from claasp.primitives.tweakable_block_ciphers.qarmav2 import QARMAv2

ROOT = Path(__file__).parents[2]
DIFFERENTIAL_CASES = (
    (Aradi, {"number_of_rounds": 2}),
    (Gift, {"number_of_rounds": 2, "block_bit_size": 64}),
    (Katan, {"number_of_rounds": 2}),
    (Ktantan, {"number_of_rounds": 2}),
    (Simeck, {"number_of_rounds": 2}),
    (Simon, {"number_of_rounds": 2}),
    (TinyJambu, {"number_of_rounds": 32}),
    (Ublock, {"number_of_rounds": 2}),
    (Ascon, {"number_of_rounds": 2}),
    (Gaston, {"number_of_rounds": 2}),
    (Gimli, {"number_of_rounds": 2}),
    (Keccak, {"number_of_rounds": 2, "word_size": 8}),
    (SpongentPi, {"number_of_rounds": 2}),
    (Xoodoo, {"number_of_rounds": 2}),
    (QARMAv2, {"number_of_rounds": 2}),
)


@pytest.mark.parametrize(("primitive_class", "parameters"), DIFFERENTIAL_CASES)
def test_selected_realizations_have_identical_contracts_and_seeded_outputs(
    primitive_class,
    parameters,
):
    descriptors = primitive_class.available_realizations()
    graphs = tuple(primitive_class.realize(item.name, **parameters) for item in descriptors)
    reference = graphs[0]
    for graph, descriptor in zip(graphs, descriptors):
        assert graph.realization is descriptor
        assert graph.realization_identity == f"{reference.family_name}:{descriptor.name}"
        assert tuple(graph.input_descriptors.items()) == tuple(reference.input_descriptors.items())
        assert graph.output.value_type == reference.output.value_type
        assert graph.kind is reference.kind

    generator = random.Random(f"M10.9e:{primitive_class.__name__}")
    for _ in range(3):
        inputs = {
            name: generator.getrandbits(item.value_type.encoded_bit_size)
            for name, item in reference.input_descriptors.items()
        }
        assert len({graph.evaluate(**inputs) for graph in graphs}) == 1


FIXTURE_CASES = (
    (
        Aradi,
        {},
        (0, 0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100),
        0x3F09ABF400E3BD7403260DEFB7C53912,
    ),
    (Simeck, {}, (0x65656877, 0x1918111009080100), 0x770D2C76),
    (Simon, {}, (0x65656877, 0x1918111009080100), 0xC69BE9BB),
    (TinyJambu, {}, (0, 0), 255845905141822593977431191925590833879),
)


@pytest.mark.parametrize(("primitive_class", "parameters", "inputs", "expected"), FIXTURE_CASES)
def test_boundary_normalized_realizations_preserve_published_fixed_vectors(
    primitive_class,
    parameters,
    inputs,
    expected,
):
    for descriptor in primitive_class.available_realizations():
        assert primitive_class.realize(descriptor.name, **parameters).evaluate(*inputs) == expected


def test_every_audited_family_and_realization_has_existing_fixed_evidence():
    records = []
    for name in ("m10_9d6_fixed_vectors.json", "m10_9d7_fixed_vectors.json"):
        records.extend(json.loads((ROOT / "migration" / name).read_text()))
    evidenced = {record["class"] for record in records}
    assert {
        "Gift",
        "Katan",
        "Ktantan",
        "TinyJambu",
        "Ublock",
        "QARMAv2",
        "Ascon",
        "Gaston",
        "Gimli",
        "Keccak",
        "SpongentPi",
        "Xoodoo",
    } <= evidenced


def test_capability_selection_uses_metadata_not_component_names():
    assert Gift.for_capabilities({"sbox_semantics"}).realization.name == "sbox"
    assert (
        Katan.for_capabilities({"feedback_register_semantics"}).realization.name
        == "feedback_register"
    )
    assert Gaston.for_capabilities({"linear_map_semantics"}).realization.name == "sbox_theta"
    assert Simon.for_capabilities({"sbox_semantics"}).realization.name == "legacy_sbox"
