"""Grouped default analysis preserves semantic evidence and discovery coverage."""

import importlib
from io import StringIO

import pytest

from claasp.analysis import ComponentAnalysisResult, PropertyClaim
from claasp.presentation import present, render_report
from claasp.primitives import Present, ToyAES


def test_each_semantic_group_is_analyzed_once_and_reporting_reuses_values(monkeypatch):
    module = importlib.import_module("claasp.analysis.component_properties")
    analyze = module.analyze_component_property
    calls = []

    def record(component, request, **kwargs):
        calls.append((id(component), request))
        return analyze(component, request, **kwargs)

    monkeypatch.setattr(module, "analyze_component_property", record)
    primitive = Present(number_of_rounds=2)
    result = primitive.analysis.component_analysis()
    assert len(calls) == len(set(calls))
    assert len(calls) == sum(len(items) for items in result.properties)
    assert sum(group.count for group in result.groups) == len(primitive.graph.components)
    sbox = next(
        items
        for group, items in zip(result.groups, result.properties, strict=True)
        if type(group.representative).__name__ == "BitVectorSBox"
    )
    assert len(sbox[0].provenance.graph_locations) == 34
    assert sbox[0].provenance.primitive == "present"
    before = len(calls)
    output = StringIO()
    result.to_terminal(file=output)
    result.to_terminal(details=True, file=output)
    assert "Component analysis" in render_report(present(result))
    assert len(calls) == before


def test_field_maps_keep_word_domain_and_exact_properties():
    result = ToyAES(word_size=3, state_size=3, number_of_rounds=2).analysis.component_analysis()
    maps = [
        items
        for group, items in zip(result.groups, result.properties, strict=True)
        if type(group.representative).__name__ == "LinearMap"
    ]
    assert maps
    assert all(item.request.domain.value == "word_linear" for items in maps for item in items)
    assert all(item.claim is PropertyClaim.EXACT for items in maps for item in items)
    assert maps[0][1].value is True


def test_grouped_result_rejects_misaligned_properties():
    result = Present(number_of_rounds=1).analysis.component_analysis()
    with pytest.raises(ValueError, match="align"):
        ComponentAnalysisResult("present", result.groups, ())


def test_discovery_does_not_expand_large_modular_addition_anfs():
    from claasp.primitives import Speck

    result = Speck(number_of_rounds=2).analysis.component_analysis()
    additions = [
        items
        for group, items in zip(result.groups, result.properties, strict=True)
        if type(group.representative).__name__ == "ModularAdd"
    ]
    assert additions
    assert all(items == () for items in additions)
