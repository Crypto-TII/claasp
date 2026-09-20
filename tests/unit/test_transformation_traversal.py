from claasp import (
    Bit,
    DependencyIndex,
    GraphSourceKind,
    Primitive,
    TransformationError,
    TransformationFailureReason,
    TransformationRecord,
    ValueType,
)
from claasp.components import Add, Identity


def _graph():
    primitive = Primitive(
        "traversal", {"left": ValueType(Bit(), (4,)), "right": ValueType(Bit(), (4,))}
    )
    primitive.add_round()
    joined = primitive.join(primitive.input("left")[:2], primitive.input("right")[:2])
    copied = primitive.add_component(Identity(joined, "copy"))
    mixed = primitive.add_component(Add((copied, primitive.input("left")), "mixed"))
    primitive.set_output(mixed)
    return primitive


def test_dependency_index_traverses_bindings_without_semantic_placeholders():
    primitive = _graph()
    index = DependencyIndex(primitive)

    binding = primitive.bindings[0]
    assert index.source(binding.binding_id).kind is GraphSourceKind.BINDING
    assert index.predecessors(binding.binding_id) == ("left", "right")
    assert index.predecessors("copy") == (binding.binding_id,)
    assert index.ancestors("mixed") == index.topological_ids
    assert index.descendants("right") == ("right", binding.binding_id, "copy", "mixed")
    assert [type(component).__name__ for component in primitive.components] == ["Identity", "Add"]


def test_dependency_boundaries_fail_with_exact_reasons():
    index = DependencyIndex(_graph())
    try:
        index.ancestors(())
    except TransformationError as error:
        assert error.reason is TransformationFailureReason.AMBIGUOUS_BOUNDARY
    else:  # pragma: no cover
        raise AssertionError("empty boundary unexpectedly accepted")

    try:
        index.descendants("missing")
    except TransformationError as error:
        assert error.reason is TransformationFailureReason.DISCONNECTED_DEPENDENCY
        assert error.source_ids == ("missing",)
    else:  # pragma: no cover
        raise AssertionError("missing source unexpectedly accepted")


def test_execution_provenance_keeps_transformations_separate_from_driver_and_realization():
    primitive = _graph()
    record = TransformationRecord("audit", (("scope", "whole"),), primitive.realization_identity)
    object.__setattr__(primitive, "_transformation_provenance", (record,))

    result = primitive.evaluate_with_trace(left=0b1010, right=0b1100)

    assert result.provenance.transformations == (record,)
    assert result.provenance.realization == primitive.realization
    assert result.provenance.driver.name == "python_scalar"
