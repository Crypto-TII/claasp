"""Paired primitive graphs with characteristic-two difference observations."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from claasp.components import Add, Xor
from claasp.domains import BinaryExtensionField, Bit, Word
from claasp.graph import (
    CompositeDefinition,
    Port,
    Primitive,
    PrimitiveKind,
    Selection,
    as_selection,
)
from claasp.graph.composite import CompositeInstance, CompositeTemplate
from claasp.provenance import TransformationRecord
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
)


@dataclass(frozen=True, slots=True)
class PairedTransformationResult:
    """A paired graph, its scopes, and typed XOR observations.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> result = Speck(number_of_rounds=1).paired_xor(shared_inputs=("key",))
        >>> (tuple(result.differences_by_input), tuple(result.primitive.input_ports))
        (('plaintext',), ('left_plaintext', 'right_plaintext', 'key'))
    """

    primitive: Primitive
    left_scope: CompositeInstance
    right_scope: CompositeInstance
    input_differences: tuple[tuple[str, Selection], ...]
    round_differences: tuple[Selection, ...]
    key_differences: tuple[Selection, ...]
    output_difference: Selection

    @property
    def differences_by_input(self) -> Mapping[str, Selection]:
        """Return non-shared input differences by original input name."""

        return dict(self.input_differences)


def _as_observation(value) -> tuple[Selection, ...]:
    if isinstance(value, (Port, Selection)):
        return (as_selection(value),)
    if isinstance(value, Mapping):
        return tuple(as_selection(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(as_selection(item) for item in value)
    raise TypeError("published paired observations must contain graph ports or selections")


def _definition_from_primitive(primitive: Primitive) -> CompositeDefinition:
    templates = tuple(
        CompositeTemplate(
            scope.path,
            scope.definition,
            scope.input_bindings,
            scope.output_bindings,
            scope.component_ids,
        )
        for scope in primitive.scopes
    )
    return CompositeDefinition(
        f"{primitive.family_name}_realization",
        tuple((name, port.value_type) for name, port in primitive.input_ports.items()),
        tuple(tuple(primitive_round.components) for primitive_round in primitive.rounds),
        primitive.bindings,
        (("output", primitive.output),),
        primitive.provenance,
        templates,
    )


def _scoped_selection(
    parent: Primitive, scope: CompositeInstance, selection: Selection
) -> Selection:
    source_id = selection.source.owner_id
    if source_id in scope.inputs:
        return scope.inputs[source_id][selection.positions]
    return parent.port(f"{scope.path}/{source_id}")[selection.positions]


def _difference_component(left: Selection, right: Selection):
    if left.value_type != right.value_type:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "paired difference operands have different value types",
            source_ids=(left.source.owner_id, right.source.owner_id),
        )
    domain = left.value_type.domain
    if isinstance(domain, Word):
        return Xor((left, right))
    if isinstance(domain, (Bit, BinaryExtensionField)):
        return Add((left, right))
    raise TransformationError(
        TransformationFailureReason.UNSUPPORTED_COMPONENT,
        f"XOR observation is unavailable for {type(domain).__name__}",
        source_ids=(left.source.owner_id, right.source.owner_id),
    )


def _scoped_observation(parent, scope, observation):
    selections = tuple(
        _scoped_selection(parent, scope, selection) for selection in _as_observation(observation)
    )
    domains = {selection.value_type.domain for selection in selections}
    if len(domains) != 1:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "one paired observation must use one scalar domain",
            source_ids=tuple(selection.source.owner_id for selection in selections),
        )
    return as_selection(parent.join(*selections))


def paired_xor_primitive(
    primitive: Primitive,
    *,
    shared_inputs: Sequence[str | int] = (),
    family_name: str | None = None,
) -> PairedTransformationResult:
    """Instantiate two primitive scopes and expose their XOR differences.

    ``shared_inputs`` expresses a single-key or otherwise shared boundary.
    Every other input receives explicit ``left_*`` and ``right_*`` values.
    Published round-state and round-key landmarks become additional typed
    difference observations without changing the graph's output contract.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> source = Speck(number_of_rounds=2)
        >>> paired = paired_xor_primitive(source, shared_inputs=("key",)).primitive
        >>> key = 0x1918111009080100
        >>> left, right = 0x6574694c, 0x6574694d
        >>> paired.evaluate(left, right, key) == source.evaluate(left, key) ^ source.evaluate(right, key)
        True
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("paired_xor_primitive requires a Primitive")
    if primitive.output is None:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive has no declared output",
        )
    shared_ports = tuple(primitive.input(selector) for selector in shared_inputs)
    shared = tuple(port.owner_id for port in shared_ports)
    if len(set(shared)) != len(shared):
        raise TransformationError(
            TransformationFailureReason.MULTIPLE_PREDECESSORS,
            "shared primitive inputs must be unique",
            source_ids=shared,
        )
    descriptors = {}
    for name, descriptor in primitive.input_descriptors.items():
        if name in shared:
            descriptors[name] = descriptor
        else:
            descriptors[f"left_{name}"] = descriptor
            descriptors[f"right_{name}"] = descriptor
    paired = Primitive(
        family_name or f"{primitive.family_name}_paired_xor",
        descriptors,
        kind=PrimitiveKind.FUNCTION,
        provenance=primitive.provenance,
    )
    paired.realization = primitive.realization
    paired.add_round()
    definition = _definition_from_primitive(primitive)
    left_bindings = {
        name: paired.input(name if name in shared else f"left_{name}")
        for name in primitive.input_ports
    }
    right_bindings = {
        name: paired.input(name if name in shared else f"right_{name}")
        for name in primitive.input_ports
    }
    left_scope = paired.add_composite(definition, left_bindings, scope_id="left")
    right_scope = paired.add_composite(definition, right_bindings, scope_id="right")

    input_differences = []
    for name in primitive.input_ports:
        if name in shared:
            continue
        difference = paired.add_component(
            _difference_component(
                paired.input(f"left_{name}").select_all(),
                paired.input(f"right_{name}").select_all(),
            )
        )
        input_differences.append((name, difference.select_all()))

    def differences(observations):
        result = []
        for observation in observations:
            left = _scoped_observation(paired, left_scope, observation)
            right = _scoped_observation(paired, right_scope, observation)
            result.append(paired.add_component(_difference_component(left, right)).select_all())
        return tuple(result)

    round_differences = differences(tuple(getattr(primitive, "round_states", ())))
    key_differences = differences(tuple(getattr(primitive, "round_keys", ())))
    output_difference = paired.add_component(
        _difference_component(
            left_scope.output(),
            right_scope.output(),
        )
    ).select_all()
    paired.set_output(output_difference)
    record = TransformationRecord(
        "paired_xor",
        (("shared_inputs", ",".join(shared)),),
        primitive.realization_identity,
    )
    object.__setattr__(
        paired,
        "_transformation_provenance",
        (*primitive.transformation_provenance, record),
    )
    return PairedTransformationResult(
        paired,
        left_scope,
        right_scope,
        tuple(input_differences),
        round_differences,
        key_differences,
        output_difference,
    )


__all__ = ["PairedTransformationResult", "paired_xor_primitive"]
