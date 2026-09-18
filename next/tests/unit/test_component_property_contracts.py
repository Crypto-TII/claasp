from dataclasses import FrozenInstanceError

import pytest

from claasp_next.analysis.component_properties import (
    ComponentAnalysisProvenance,
    ComponentProperty,
    ComponentPropertyResult,
    DiagnosticCode,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
    unavailable_result,
)


def test_exact_contract_is_immutable_and_freezes_nested_values():
    request = PropertyRequest(
        ComponentProperty.RANK,
        PropertyDomain.BIT_LINEAR,
        (("orientation", {"rows": [0, 1]}),),
    )
    provenance = ComponentAnalysisProvenance("linear_map:bit:2x2", "binary_elimination")
    result = ComponentPropertyResult(request, PropertyClaim.EXACT, {"rank": 2}, True, provenance)

    assert result.value["rank"] == 2
    assert request.option_map["orientation"]["rows"] == (0, 1)
    with pytest.raises(TypeError):
        result.value["rank"] = 1
    with pytest.raises(FrozenInstanceError):
        result.complete = False


def test_exact_claim_requires_complete_coverage():
    request = PropertyRequest(ComponentProperty.ORDER, PropertyDomain.BIT_LINEAR)
    provenance = ComponentAnalysisProvenance("linear_map:bit:2x2", "bounded_enumeration")
    with pytest.raises(ValueError, match="exact result"):
        ComponentPropertyResult(request, PropertyClaim.EXACT, 3, False, provenance)


def test_unavailable_contract_has_precise_typed_diagnostic():
    request = PropertyRequest(ComponentProperty.MDS, PropertyDomain.WORD_OPERATION)
    provenance = ComponentAnalysisProvenance("rotate:word:8", "core_dispatch")
    result = unavailable_result(
        request,
        provenance,
        DiagnosticCode.INAPPLICABLE_DOMAIN,
        "MDS status applies to square linear maps, not rotations",
    )

    assert result.claim is PropertyClaim.UNAVAILABLE
    assert result.diagnostic.code is DiagnosticCode.INAPPLICABLE_DOMAIN
    assert not result.is_available


def test_component_ids_are_only_optional_evidence_locations():
    provenance = ComponentAnalysisProvenance(
        "lookup_table:4->4:12c5",
        "exact_enumeration",
        primitive="present",
        realization="canonical",
        graph_locations=("round[1]/sbox_1_0",),
    )
    assert "sbox_1_0" not in provenance.semantic_identity
    assert provenance.graph_locations == ("round[1]/sbox_1_0",)
