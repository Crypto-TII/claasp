import pytest

from claasp_next.presentation import (
    Applicability,
    DiagnosticCode,
    EvidenceClass,
    MathematicalProvenance,
    PresentationDiagnostic,
    PresentationEvidence,
    PresentationProvenance,
    ReproducibilityMetadata,
)


def diagnostic(message="not available"):
    return PresentationDiagnostic(DiagnosticCode.MISSING_EVIDENCE, message)


def test_evidence_never_promotes_non_exact_results():
    exact = PresentationEvidence(EvidenceClass.EXACT)
    empirical = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=False)
    bounded = PresentationEvidence(
        EvidenceClass.PROVED_BOUND, complete=False, bound_direction="upper"
    )
    unavailable = PresentationEvidence(EvidenceClass.UNAVAILABLE, diagnostic=diagnostic())

    assert exact.is_successful_exact
    assert not empirical.is_successful_exact
    assert not bounded.is_successful_exact
    assert not unavailable.is_successful_exact


def test_inapplicable_and_terminal_states_require_diagnostics():
    with pytest.raises(ValueError, match="requires a diagnostic"):
        PresentationEvidence(EvidenceClass.SKIPPED)
    with pytest.raises(ValueError, match="classified as unavailable"):
        PresentationEvidence(EvidenceClass.EXACT, applicability=Applicability.INAPPLICABLE)

    value = PresentationEvidence(
        EvidenceClass.UNAVAILABLE,
        applicability=Applicability.INAPPLICABLE,
        diagnostic=PresentationDiagnostic(DiagnosticCode.INAPPLICABLE, "not defined"),
    )
    assert value.applicability is Applicability.INAPPLICABLE


def test_provenance_fields_remain_separate_and_metadata_is_ordered():
    reproducibility = ReproducibilityMetadata(
        ("sha256:abc",), (("dataset", 7), ("split", 19)), (("python", "3.11"),)
    )
    provenance = PresentationProvenance(
        MathematicalProvenance("exhaustive lookup", ("FIPS-197",), ("aes-sbox",)),
        reproducibility=reproducibility,
    )
    assert provenance.mathematical.method == "exhaustive lookup"
    assert provenance.primitive is None
    assert provenance.execution is None
    assert provenance.reproducibility.dataset_identities == ("sha256:abc",)

    with pytest.raises(ValueError, match="sorted deterministically"):
        ReproducibilityMetadata(seeds=(("z", 1), ("a", 2)))


def test_diagnostics_have_stable_codes_and_unique_details():
    value = PresentationDiagnostic(
        DiagnosticCode.UNSUPPORTED_RESULT,
        "unsupported object",
        (("type", "object"),),
    )
    assert value.code.value == "unsupported_result"
    with pytest.raises(ValueError, match="unique"):
        PresentationDiagnostic(
            DiagnosticCode.UNSUPPORTED_REQUEST, "bad", (("kind", "a"), ("kind", "b"))
        )
