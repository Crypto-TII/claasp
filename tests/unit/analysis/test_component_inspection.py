"""Convenient selection preserves exact semantics, domains and evidence."""

import importlib
from io import StringIO

import pytest

from claasp import PrimitiveBuilder, UnitArrayType
from claasp.analysis import ComponentTableResult, PropertyClaim
from claasp.components import BitVectorSBox
from claasp.composites import AESMixColumn, AESRound
from claasp.presentation import present, render_report
from claasp.primitives import Present, ToyAES
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics
from claasp.unit_types import Bit


def test_selection_groups_equivalent_occurrences_without_running_analysis(monkeypatch):
    module = importlib.import_module("claasp.analysis.component_inspection")

    def forbidden(*args, **kwargs):
        raise AssertionError("selection must not compute properties")

    monkeypatch.setattr(module, "analyze_component_property", forbidden)
    primitive = Present(number_of_rounds=2)
    assert primitive.analysis.component("sbox").count == 34
    state = primitive.analysis.component("permutation", bit_size=64)
    key = primitive.analysis.component("permutation", bit_size=80)
    assert state.group.key != key.group.key
    assert primitive.analysis.component("permutation", index=1).group == key.group


@pytest.mark.parametrize(
    "kind, options, message",
    [
        ("permutation", {}, "specify bit_size or index"),
        ("missing", {}, "no component group"),
        ("sbox", {"index": 1}, "outside"),
        ("sbox", {"index": -1}, "nonnegative"),
        ("sbox", {"index": True}, "nonnegative"),
        ("sbox", {"bit_size": 0}, "positive"),
        ("", {}, "nonempty"),
    ],
)
def test_selection_requires_an_unambiguous_valid_match(kind, options, message):
    with pytest.raises(ValueError, match=message):
        Present(number_of_rounds=2).analysis.component(kind, **options)


def test_property_results_preserve_group_provenance_and_do_not_recompute_on_report(monkeypatch):
    sbox = Present(number_of_rounds=2).analysis.component("sbox")
    properties = sbox.properties("differential_uniformity", "boomerang_uniformity")
    assert [result.value for result in properties] == [4, 16]
    assert len(properties) == 2
    assert len(properties[0].provenance.graph_locations) == 34
    assert properties[0].provenance.primitive == "present"
    assert properties[0].request.domain.value == "lookup_table"
    module = importlib.import_module("claasp.analysis.component_inspection")

    def forbidden(*args, **kwargs):
        raise AssertionError("reporting must reuse the measurement")

    monkeypatch.setattr(module, "analyze_component_property", forbidden)
    output = StringIO()
    properties.to_terminal(file=output)
    properties.to_terminal(details=True, file=output)
    assert "round[" in output.getvalue()
    assert "boomerang_uniformity" in render_report(present(properties))


def test_typed_domains_and_exact_search_options_are_forwarded():
    mix = AESRound().analyze().component("linear_map")
    assert mix.properties("rank")[0].value == 16
    assert mix.properties("rank", domain="bit_linear")[0].value == 128
    unknown = mix.properties("differential_branch_number", maximum_vectors=1)[0]
    assert unknown.claim is PropertyClaim.UNAVAILABLE
    assert unknown.diagnostic.code.value == "budget_exhausted"
    column = AESMixColumn().analyze().component("linear_map")
    assert column.properties("order", maximum_steps=4)[0].value == 4
    assert column.properties("order", maximum_steps=1)[0].claim is PropertyClaim.UNAVAILABLE
    assert [result.value for result in column.properties()] == [4, True, 5, 5]


@pytest.mark.parametrize(
    "names, options",
    [
        (("rank",), {"maximum_input_weight": 1}),
        (("rank",), {"maximum_vectors": 1}),
        (("rank",), {"maximum_steps": 1}),
        (("differential_branch_number",), {"maximum_input_weight": 1, "maximum_vectors": 1}),
    ],
)
def test_search_options_cannot_silently_apply_to_other_properties(names, options):
    with pytest.raises(ValueError):
        AESMixColumn().analyze().component("linear_map").properties(*names, **options)


def test_bounded_results_keep_bound_claim_and_realization_provenance():
    mix = AESRound().analyze().component("linear_map")
    bound = mix.properties("differential_branch_number", maximum_input_weight=1)[0]
    assert bound.value == 5 and not bound.complete
    assert bound.claim is PropertyClaim.PROVED_UPPER_BOUND
    assert bound.provenance.primitive == "AESRound"
    assert bound.provenance.realization == mix.realization
    assert len(bound.provenance.graph_locations) == 1
    assert bound.provenance.driver.name == "bounded_branch_enumeration"


def test_ddt_matches_independent_semantics_and_preserves_full_table():
    sbox = Present(number_of_rounds=2).analysis.component("sbox")
    ddt = sbox.ddt()
    assert (
        ddt.counts
        == SBoxTransitionSemantics(sbox.group.representative.table).difference_distribution_table()
    )
    assert ddt.claim is PropertyClaim.EXACT
    assert len(ddt.provenance.graph_locations) == 34
    output = StringIO()
    ddt.to_terminal(file=output)
    assert "Input XOR" in output.getvalue()
    report = present(ddt)
    assert "exact" in render_report(report)
    evidence = report.sections[0].tables[0].rows[0].cells[1].evidence
    assert evidence is not None and evidence.classification.value == "exact"
    with pytest.raises(ValueError, match="S-box"):
        AESMixColumn().analyze().component("linear_map").ddt()


def test_rectangular_and_parallel_field_sboxes_keep_per_lookup_widths():
    builder = PrimitiveBuilder("rectangular", {"data": UnitArrayType(Bit(), (2,))})
    builder.add_round()
    output = builder.add_component(
        BitVectorSBox(builder.input("data"), (0, 1, 3, 7), output_bit_size=3)
    )
    ddt = builder.build(output).analysis.component("sbox").ddt()
    assert (ddt.input_bit_size, ddt.output_bit_size) == (2, 3)
    assert ddt.counts[1] == (0, 2, 0, 0, 2, 0, 0, 0)
    parallel = (
        ToyAES(word_size=3, state_size=3, number_of_rounds=2)
        .analysis.component("sbox", bit_size=27)
        .ddt()
    )
    assert (parallel.input_bit_size, parallel.output_bit_size) == (3, 3)
    assert all(sum(row) == 8 for row in parallel.counts)


def test_ddt_contract_rejects_wrong_dimensions_or_nonexhaustive_counts():
    ddt = Present(number_of_rounds=1).analysis.component("sbox").ddt()
    with pytest.raises(ValueError, match="dimensions"):
        ComponentTableResult("bad", 4, 4, ddt.counts[1:], ddt.provenance)
    with pytest.raises(ValueError, match="count every input"):
        ComponentTableResult("bad", 1, 1, ((0, 0), (1, 1)), ddt.provenance)


def test_single_column_composite_has_known_aes_output_and_exact_branch_number():
    column = AESMixColumn()
    assert column.evaluate(0xDB135345) == 0x8E4DA1BC
    properties = (
        column.analyze().component("linear_map").properties("mds", "differential_branch_number")
    )
    assert [result.value for result in properties] == [True, 5]
    assert all(result.claim is PropertyClaim.EXACT for result in properties)
