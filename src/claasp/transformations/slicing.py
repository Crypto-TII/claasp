"""Validated dependency and round slices of immutable primitive graphs."""

from collections.abc import Mapping, Sequence
from copy import copy
from dataclasses import dataclass

from claasp.graph import (
    Port,
    PortLike,
    Primitive,
    PrimitiveInput,
    Selection,
    ValueType,
    as_selection,
)
from claasp.graph.composite import CompositeInstance
from claasp.provenance import TransformationRecord
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
    TransformationResult,
)
from claasp.transformations.traversal import DependencyIndex, GraphSourceKind


@dataclass(frozen=True, slots=True)
class DependencySplit:
    """Inclusive backward and forward closures around two boundaries.

    EXAMPLES::

        >>> DependencySplit(("input", "top"), ("bottom", "output")).top
        ('input', 'top')
    """

    top: tuple[str, ...]
    bottom: tuple[str, ...]


def split_dependencies(
    primitive: Primitive,
    *,
    top_outputs: str | Sequence[str],
    bottom_inputs: str | Sequence[str],
) -> DependencySplit:
    """Return typed predecessor and descendant closures for split boundaries.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> primitive = Speck(number_of_rounds=2)
        >>> first = primitive.graph.round_outputs[0][0].owner_id
        >>> second = primitive.graph.round_outputs[1][0].owner_id
        >>> split = split_dependencies(primitive, top_outputs=first, bottom_inputs=second)
        >>> first in split.top and second in split.bottom
        True
    """

    index = DependencyIndex(primitive)
    return DependencySplit(
        index.ancestors(top_outputs),
        index.descendants(bottom_inputs),
    )


def _as_values(value) -> tuple[Selection, ...]:
    if isinstance(value, (Port, Selection)):
        return (as_selection(value),)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        result = tuple(as_selection(item) for item in value)
        if result:
            return result
    raise TypeError("a graph boundary must be a port, selection, or non-empty sequence of them")


def _normalize_outputs(primitive: Primitive, outputs) -> tuple[Selection, ...]:
    if outputs is None:
        if primitive.graph.output is None:
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "primitive has no declared output",
            )
        return (primitive.graph.output,)
    if isinstance(outputs, str):
        return (primitive.graph.port(outputs).select_all(),)
    return _as_values(outputs)


def _validate_selection(primitive: Primitive, selection: Selection) -> None:
    try:
        actual = primitive.graph.port(selection.source.owner_id)
    except KeyError as error:
        raise TransformationError(
            TransformationFailureReason.DISCONNECTED_DEPENDENCY,
            "boundary source is not in the primitive",
            source_ids=(selection.source.owner_id,),
        ) from error
    if actual != selection.source:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "boundary port type does not match the primitive",
            source_ids=(selection.source.owner_id,),
        )


def _boundary_descriptors(primitive, inputs):
    descriptors = {}
    pieces_by_source = {}
    if inputs is None:
        return descriptors, pieces_by_source
    if not isinstance(inputs, Mapping) or not inputs:
        raise TypeError("slice inputs must be a non-empty mapping")
    for name, value in inputs.items():
        if not isinstance(name, str) or not name:
            raise ValueError("slice input names must be non-empty strings")
        pieces = _as_values(value)
        for piece in pieces:
            _validate_selection(primitive, piece)
        domain = pieces[0].value_type.domain
        if any(piece.value_type.domain != domain for piece in pieces[1:]):
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "one boundary input must use one scalar domain",
                source_ids=tuple(piece.source.owner_id for piece in pieces),
            )
        descriptor = PrimitiveInput(
            ValueType(domain, (sum(piece.value_type.unit_count for piece in pieces),)), role=name
        )
        descriptors[name] = descriptor
        offset = 0
        for piece in pieces:
            source_id = piece.source.owner_id
            if source_id in pieces_by_source:
                raise TransformationError(
                    TransformationFailureReason.MULTIPLE_PREDECESSORS,
                    "one source is represented by more than one boundary input",
                    source_ids=(source_id,),
                )
            pieces_by_source[source_id] = (name, piece.positions, offset)
            offset += len(piece.positions)
    return descriptors, pieces_by_source


def _required_sources(index, output_ids, boundary_ids):
    required = set()
    visiting = list(output_ids)
    while visiting:
        source_id = visiting.pop()
        if source_id in required:
            continue
        required.add(source_id)
        if source_id not in boundary_ids:
            visiting.extend(index.predecessors(source_id))
    return required


def slice_primitive(
    primitive: Primitive,
    outputs=None,
    *,
    inputs: Mapping[str, PortLike | Sequence[PortLike]] | None = None,
    family_name: str | None = None,
) -> TransformationResult:
    """Return the validated dependency slice between explicit graph boundaries.

    Structural joins, ordered views, PackBits, and UnpackBits remain bindings.
    A boundary may join several homogeneous selections into one new input.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> primitive = Speck(number_of_rounds=2)
        >>> result = slice_primitive(primitive, primitive.graph.round_outputs[0])
        >>> hex(result.primitive.evaluate(0x6574694c, 0x1918111009080100))
        '0x5316f627'
        >>> len(result.primitive.graph.components) < len(primitive.graph.components)
        True
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("slice_primitive requires a Primitive")
    output_selections = _normalize_outputs(primitive, outputs)
    for selection in output_selections:
        _validate_selection(primitive, selection)
    boundary_descriptors, boundary_by_source = _boundary_descriptors(primitive, inputs)
    index = DependencyIndex(primitive)
    required = _required_sources(
        index,
        tuple(selection.source.owner_id for selection in output_selections),
        set(boundary_by_source),
    )

    for source_id in primitive.graph.input_ports:
        if source_id in required and source_id not in boundary_by_source:
            boundary_descriptors[source_id] = primitive.graph.input_descriptor(source_id)

    exact_contract = (
        inputs is None
        and len(output_selections) == 1
        and primitive.graph.output == output_selections[0]
        and set(primitive.graph.input_ports) <= required
    )
    derived = Primitive(
        family_name or f"{primitive.family_name}_slice",
        boundary_descriptors,
        kind=primitive.kind if exact_contract else None,
        provenance=primitive.provenance,
    )
    derived.realization = primitive.realization
    old_transformations = primitive.transformation_provenance
    source_ports: dict[str, Port] = {}
    boundary_positions = {}
    for name in boundary_descriptors:
        source_ports[name] = derived.graph.input(name)
    for source_id, (_name, positions, offset) in boundary_by_source.items():
        boundary_positions[source_id] = {
            position: offset + relative for relative, position in enumerate(positions)
        }
    for input_name in primitive.graph.input_ports:
        if input_name in required and input_name not in boundary_by_source:
            source_ports[input_name] = derived.graph.input(input_name)

    def remap(selection: Selection) -> Selection:
        source_id = selection.source.owner_id
        if source_id in boundary_positions:
            position_map = boundary_positions[source_id]
            try:
                positions = tuple(position_map[position] for position in selection.positions)
            except KeyError as error:
                raise TransformationError(
                    TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                    "boundary omits a logical unit required by the slice",
                    source_ids=(source_id,),
                ) from error
            name = boundary_by_source[source_id][0]
            return derived.graph.input(name)[positions]
        try:
            return source_ports[source_id][selection.positions]
        except KeyError as error:
            raise TransformationError(
                TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                "required source was not reconstructed",
                source_ids=(source_id,),
            ) from error

    binding_by_id = {binding.binding_id: binding for binding in primitive.graph.bindings}
    component_by_id = {
        component.component_id: component for component in primitive.graph.components
    }
    round_by_component = {
        component.component_id: primitive_round.number
        for primitive_round in primitive.graph.rounds
        for component in primitive_round.components
    }
    active_round = None
    derived_round_by_original = {}
    for source_id in index.topological_ids:
        if source_id not in required or source_id in boundary_by_source:
            continue
        source = index.source(source_id)
        if source.kind is GraphSourceKind.BINDING:
            binding = binding_by_id[source_id]
            source_ports[source_id] = derived._add_binding(
                binding.kind,
                tuple(remap(item) for item in binding.inputs),
                binding.output_type,
                word_width=binding.word_width,
                binding_id=binding.binding_id,
            )
        elif source.kind is GraphSourceKind.COMPONENT:
            original_round = round_by_component[source_id]
            if original_round != active_round:
                derived_round_by_original[original_round] = derived._builder.add_round()
                active_round = original_round
            component = copy(component_by_id[source_id])
            object.__setattr__(component, "inputs", tuple(remap(item) for item in component.inputs))
            source_ports[source_id] = derived._builder.add_component(component)

    transformed_outputs = tuple(remap(selection) for selection in output_selections)
    derived._builder.set_output(
        transformed_outputs if len(transformed_outputs) > 1 else transformed_outputs[0]
    )

    # Complete composite scopes survive as hierarchy overlays; partial scopes
    # stay flat rather than claiming to be complete reusable instances.
    for scope in primitive.graph.scopes:
        if not set(scope.component_ids) <= required:
            continue
        try:
            instance = CompositeInstance(
                scope.path,
                scope.definition,
                tuple((name, remap(value)) for name, value in scope.input_bindings),
                tuple((name, remap(value)) for name, value in scope.output_bindings),
                scope.component_ids,
                derived,
            )
        except TransformationError:
            continue
        derived._scopes[scope.path] = instance
        original_round = round_by_component[scope.component_ids[0]]
        if original_round in derived_round_by_original:
            derived_round_by_original[original_round]._append_scope(instance)

    operation = "slice"
    parameters = (
        ("outputs", ",".join(selection.source.owner_id for selection in output_selections)),
        ("inputs", ",".join(boundary_descriptors)),
    )
    record = TransformationRecord(operation, parameters, primitive.realization_identity)
    object.__setattr__(derived, "_transformation_provenance", (*old_transformations, record))
    source_map = tuple(
        (source_id, source_ports[source_id].owner_id)
        for source_id in index.topological_ids
        if source_id in source_ports
    )
    return TransformationResult(derived, source_map)


def _round_observation(primitive: Primitive, round_number: int):
    states = tuple(primitive.graph.round_outputs)
    if round_number < 0 or round_number >= len(states):
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive does not publish the requested round-state boundary",
            source_ids=(str(round_number),),
        )
    state = states[round_number]
    if isinstance(state, Mapping):
        if "state" in state:
            return state["state"]
        return tuple(state.values())
    return state


def slice_rounds(
    primitive: Primitive,
    start_round: int = 0,
    end_round: int | None = None,
) -> TransformationResult:
    """Slice published round-state boundaries inclusively.

    Earlier auxiliary/key-schedule dependencies remain when needed. Use the
    explicit key-schedule transformation when independent round-key inputs are
    desired.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> primitive = Speck(number_of_rounds=3)
        >>> reduced = slice_rounds(primitive, 0, 1).primitive
        >>> reduced.evaluate(0x6574694c, 0x1918111009080100)
        937422656
    """

    if not isinstance(start_round, int) or isinstance(start_round, bool):
        raise TypeError("start_round must be an integer")
    if end_round is None:
        end_round = len(primitive.graph.rounds) - 1
    if not isinstance(end_round, int) or isinstance(end_round, bool):
        raise TypeError("end_round must be an integer")
    if start_round < 0 or end_round < start_round or end_round >= len(primitive.graph.rounds):
        raise ValueError("round range lies outside the primitive")
    outputs = _round_observation(primitive, end_round)
    boundaries = (
        None if start_round == 0 else {"state": _round_observation(primitive, start_round - 1)}
    )
    result = slice_primitive(
        primitive,
        outputs,
        inputs=boundaries,
        family_name=f"{primitive.family_name}_rounds_{start_round}_{end_round}",
    )
    records = result.primitive.transformation_provenance
    replacement = TransformationRecord(
        "slice_rounds",
        (("start", str(start_round)), ("end", str(end_round))),
        primitive.realization_identity,
    )
    object.__setattr__(result.primitive, "_transformation_provenance", (*records[:-1], replacement))
    return result


def reduce_rounds(primitive: Primitive, number_of_rounds: int) -> TransformationResult:
    """Return the prefix ending at a published round-state boundary.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> len(reduce_rounds(Speck(number_of_rounds=3), 2).primitive.graph.rounds) <= 2
        True
    """

    if not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool):
        raise TypeError("number_of_rounds must be an integer")
    if number_of_rounds <= 0:
        raise ValueError("number_of_rounds must be positive")
    return slice_rounds(primitive, 0, number_of_rounds - 1)


__all__ = [
    "DependencySplit",
    "reduce_rounds",
    "slice_primitive",
    "slice_rounds",
    "split_dependencies",
]
