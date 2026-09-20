import pytest

from claasp.analysis import AttackTarget
from claasp.annotations import (
    AnnotationEntry,
    AnnotationRole,
    ExecutionTrace,
    GraphAnnotation,
    LeakageSample,
    SideChannelTrace,
)
from claasp.primitives import Present
from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations import Artifact, Representation
from claasp.representations.execution import ScalarExecutionDriver
from claasp.semantics import CONCRETE, LEAKAGE, SemanticType
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


def test_graph_annotations_are_typed_validated_and_immutable():
    primitive = Present(number_of_rounds=1)
    annotation = GraphAnnotation(
        primitive,
        CONCRETE,
        (
            AnnotationEntry("plaintext", AnnotationRole.INPUT, 0),
            AnnotationEntry(primitive.components[0].component_id, AnnotationRole.COMPONENT, 1),
            AnnotationEntry("primitive_output", AnnotationRole.OUTPUT, 2),
        ),
    )
    trace = ExecutionTrace(annotation)

    assert trace.value_of("plaintext") == 0
    assert trace.value_of("primitive_output") == 2
    with pytest.raises(AttributeError):
        trace.annotation = annotation


def test_annotations_reject_unknown_sources_and_semantic_type_confusion():
    primitive = Present(number_of_rounds=1)
    with pytest.raises(ValueError, match="unknown primitive component"):
        GraphAnnotation(
            primitive,
            CONCRETE,
            (AnnotationEntry("not_in_graph", AnnotationRole.COMPONENT, 0),),
        )
    leakage = GraphAnnotation(primitive, LEAKAGE, ())
    with pytest.raises(ValueError, match="concrete"):
        ExecutionTrace(leakage)
    assert SideChannelTrace(leakage, (LeakageSample("sbox_1_0", 0.5, 0),)).samples[0].value == 0.5


def test_semantic_types_are_extensible_and_artifacts_name_representations():
    custom = SemanticType("my_attack", "Experimental propagation semantics")
    representation = Representation("smtlib2", "application/smtlib")
    artifact = Artifact(representation, "(check-sat)\n", (custom.name, "unit-test"))

    assert artifact.representation.name == "smtlib2"
    assert artifact.provenance == ("my_attack", "unit-test")
    assert AttackTarget.KEY_RECOVERY.value == "key_recovery"


def test_direct_execution_returns_a_concrete_graph_trace():
    primitive = Present(number_of_rounds=1)
    result = ScalarExecutionDriver().evaluate(
        primitive,
        {"plaintext": (0,) * 64, "key": (0,) * 80},
    )

    assert isinstance(result.trace, ExecutionTrace)
    assert result.trace.annotation.primitive is primitive
    assert result.trace.value_of("plaintext") == (0,) * 64
    assert result.trace.annotation.semantics is CONCRETE
    assert result.provenance.realization_identity == "present:default"
    assert result.realization is primitive.realization
    assert result.execution_engine.name == "python_scalar"
    assert result.execution_engine.kind.value == "execution_engine"
    assert result.trace.annotation.realization_identity == "present:default"


def test_representation_artifact_can_retain_typed_result_provenance():
    primitive = Present(number_of_rounds=1)
    execution = ScalarExecutionDriver().evaluate(
        primitive, {"plaintext": (0,) * 64, "key": (0,) * 80}
    )
    artifact = Artifact(
        Representation("trace", "application/json"),
        {},
        ("unit-test",),
        execution.provenance,
    )
    assert artifact.result_provenance.realization is primitive.realization
    assert artifact.result_provenance.driver.name == "python_scalar"


def test_cryptanalytic_trail_uses_the_same_annotation_foundation():
    primitive = Present(number_of_rounds=1)
    component = next(item for item in primitive.components if item.component_id == "sbox_1_0")
    transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(1, 3)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(1 << 60, 64),
        XorDifference(0, 64),
        (TrailStep(component.component_id, transition),),
    )

    annotation = trail.annotate(primitive)
    assert annotation.semantics.name == "xor_differential"
    assert annotation.value_of(component.component_id) == transition
