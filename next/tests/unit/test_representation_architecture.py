import pytest

from claasp_next.analysis import AttackTarget
from claasp_next.annotations import (
    AnnotationEntry, AnnotationRole, ExecutionTrace, GraphAnnotation,
    LeakageSample, SideChannelTrace,
)
from claasp_next.ciphers import PresentBlockCipher
from claasp_next.interpretations import CONCRETE, LEAKAGE, Interpretation
from claasp_next.interpretations.cryptanalysis import (
    SBoxTransitionSemantics, Trail, TrailKind, TrailStep, XorDifference,
)
from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX
from claasp_next.representations import Artifact, Representation
from claasp_next.representations.execution import ScalarExecutionDriver


def test_graph_annotations_are_typed_validated_and_immutable():
    cipher = PresentBlockCipher(number_of_rounds=1)
    annotation = GraphAnnotation(
        cipher,
        CONCRETE,
        (
            AnnotationEntry("plaintext", AnnotationRole.INPUT, 0),
            AnnotationEntry(cipher.components[0].component_id, AnnotationRole.COMPONENT, 1),
            AnnotationEntry("cipher_output", AnnotationRole.OUTPUT, 2),
        ),
    )
    trace = ExecutionTrace(annotation)

    assert trace.value_of("plaintext") == 0
    assert trace.value_of("cipher_output") == 2
    with pytest.raises(AttributeError):
        trace.annotation = annotation


def test_annotations_reject_unknown_sources_and_semantic_type_confusion():
    cipher = PresentBlockCipher(number_of_rounds=1)
    with pytest.raises(ValueError, match="unknown cipher component"):
        GraphAnnotation(
            cipher, CONCRETE,
            (AnnotationEntry("not_in_graph", AnnotationRole.COMPONENT, 0),),
        )
    leakage = GraphAnnotation(cipher, LEAKAGE, ())
    with pytest.raises(ValueError, match="concrete"):
        ExecutionTrace(leakage)
    assert SideChannelTrace(leakage, (LeakageSample("sbox_1_0", 0.5, 0),)).samples[0].value == 0.5


def test_interpretations_are_extensible_and_artifacts_name_representations():
    custom = Interpretation("my_attack", "Experimental propagation semantics")
    representation = Representation("smtlib2", "application/smtlib")
    artifact = Artifact(representation, "(check-sat)\n", (custom.name, "unit-test"))

    assert artifact.representation.name == "smtlib2"
    assert artifact.provenance == ("my_attack", "unit-test")
    assert AttackTarget.KEY_RECOVERY.value == "key_recovery"


def test_direct_execution_returns_a_concrete_graph_trace():
    cipher = PresentBlockCipher(number_of_rounds=1)
    result = ScalarExecutionDriver().evaluate(
        cipher,
        {"plaintext": (0,) * 64, "key": (0,) * 80},
    )

    assert isinstance(result.trace, ExecutionTrace)
    assert result.trace.annotation.cipher is cipher
    assert result.trace.value_of("plaintext") == (0,) * 64
    assert result.trace.annotation.interpretation is CONCRETE


def test_cryptanalytic_trail_uses_the_same_annotation_foundation():
    cipher = PresentBlockCipher(number_of_rounds=1)
    component = next(item for item in cipher.components if item.component_id == "sbox_1_0")
    transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(1, 3)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1 << 60, 64),
        XorDifference(0, 64),
        (TrailStep(component.component_id, transition),),
    )

    annotation = trail.annotate(cipher)
    assert annotation.interpretation.name == "xor_differential"
    assert annotation.value_of(component.component_id) == transition
