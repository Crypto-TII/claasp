"""Immutable editor-style transformations for typed primitive graphs."""

from copy import copy

from claasp.components import (
    Add,
    LinearMap,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    Xor,
)
from claasp.domains import Word
from claasp.graph import (
    InputVisibility,
    Primitive,
    PrimitiveInput,
    PrimitiveKind,
)
from claasp.graph.composite import CompositeInstance
from claasp.provenance import TransformationRecord
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
    TransformationResult,
)
from claasp.transformations.slicing import slice_primitive
from claasp.transformations.traversal import DependencyIndex, GraphSourceKind


def _record(derived, source, operation, parameters=()):
    record = TransformationRecord(operation, parameters, source.realization_identity)
    object.__setattr__(
        derived,
        "_transformation_provenance",
        (*source.transformation_provenance, record),
    )


def prune_orphans(primitive: Primitive) -> TransformationResult:
    """Return the validated output dependency closure of ``primitive``.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> source = Speck(number_of_rounds=1)
        >>> prune_orphans(source).primitive.evaluate(0x6574694c, 0x1918111009080100) == source.evaluate(0x6574694c, 0x1918111009080100)
        True
    """

    result = slice_primitive(primitive, family_name=f"{primitive.family_name}_pruned")
    _record(result.primitive, primitive, "prune_orphans")
    return result


def _input_dependencies(primitive, index):
    dependencies = {}
    for source_id in index.topological_ids:
        source = index.source(source_id)
        if source.kind is GraphSourceKind.INPUT:
            dependencies[source_id] = frozenset((source_id,))
        else:
            dependencies[source_id] = frozenset(
                name
                for predecessor in index.predecessors(source_id)
                for name in dependencies[predecessor]
            )
    return dependencies


def _round_key_boundaries(primitive, index, dependencies, secret_inputs):
    positions = {}
    order = []
    for component in primitive.graph.components:
        component_dependencies = dependencies[component.component_id]
        if component_dependencies <= secret_inputs:
            continue
        for selection in component.inputs:
            source_id = selection.source.owner_id
            source_dependencies = dependencies[source_id]
            if source_dependencies and source_dependencies <= secret_inputs:
                if source_id not in positions:
                    positions[source_id] = []
                    order.append(source_id)
                for position in selection.positions:
                    if position not in positions[source_id]:
                        positions[source_id].append(position)
    return tuple((source_id, tuple(positions[source_id])) for source_id in order)


def _zero_neutral_data_input(component, dependencies, secret_inputs):
    data_indices = tuple(
        index
        for index, selection in enumerate(component.inputs)
        if not (
            dependencies[selection.source.owner_id]
            and dependencies[selection.source.owner_id] <= secret_inputs
        )
    )
    key_indices = tuple(
        index for index in range(len(component.inputs)) if index not in data_indices
    )
    if len(data_indices) != 1 or not key_indices:
        return None
    if isinstance(component, (Xor, Add, ModularAdd)):
        return data_indices[0]
    if isinstance(component, ModularSubtract) and data_indices == (0,):
        return 0
    return None


def _rebuild_without_key_injections(primitive, index, dependencies, secret_inputs):
    injections = {}
    for component in primitive.graph.components:
        source_dependencies = dependencies[component.component_id]
        if source_dependencies <= secret_inputs:
            continue
        has_key = any(
            dependencies[item.source.owner_id]
            and dependencies[item.source.owner_id] <= secret_inputs
            for item in component.inputs
        )
        if not has_key:
            continue
        data_index = _zero_neutral_data_input(component, dependencies, secret_inputs)
        if data_index is None:
            raise TransformationError(
                TransformationFailureReason.UNSUPPORTED_COMPONENT,
                "key injection is not a recognized zero-neutral operation",
                source_ids=(component.component_id,),
            )
        if component.inputs[data_index].value_type != component.output_type:
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "key injection data input does not match its output type",
                source_ids=(component.component_id,),
            )
        injections[component.component_id] = component.inputs[data_index]

    required = set()
    visiting = [primitive.graph.output.source.owner_id]
    while visiting:
        source_id = visiting.pop()
        if source_id in required:
            continue
        required.add(source_id)
        if source_id in injections:
            visiting.append(injections[source_id].source.owner_id)
        else:
            visiting.extend(index.predecessors(source_id))

    inputs = {
        name: descriptor
        for name, descriptor in primitive.graph.input_descriptors.items()
        if name in required and name not in secret_inputs
    }
    derived = Primitive(
        f"{primitive.family_name}_without_key_injection",
        inputs,
        kind=PrimitiveKind.FUNCTION,
        provenance=primitive.provenance,
    )
    derived.realization = primitive.realization
    ports = {name: derived.graph.input(name) for name in inputs}
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

    def remap(selection):
        try:
            return ports[selection.source.owner_id][selection.positions]
        except KeyError as error:
            raise TransformationError(
                TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                "key removal left a required source unavailable",
                source_ids=(selection.source.owner_id,),
            ) from error

    for source_id in index.topological_ids:
        if source_id not in required or source_id in inputs:
            continue
        if source_id in injections:
            ports[source_id] = remap(injections[source_id])
            continue
        source = index.source(source_id)
        if source.kind is GraphSourceKind.BINDING:
            binding = binding_by_id[source_id]
            ports[source_id] = derived._add_binding(
                binding.kind,
                tuple(remap(item) for item in binding.inputs),
                binding.output_type,
                word_width=binding.word_width,
            )
        elif source.kind is GraphSourceKind.COMPONENT:
            component = component_by_id[source_id]
            original_round = round_by_component[source_id]
            if original_round != active_round:
                derived._builder.add_round()
                active_round = original_round
            clone = copy(component)
            object.__setattr__(clone, "component_id", None)
            object.__setattr__(clone, "inputs", tuple(remap(item) for item in component.inputs))
            ports[source_id] = derived._builder.add_component(clone)
    derived._builder.set_output(remap(primitive.graph.output))
    _record(
        derived,
        primitive,
        "remove_key_schedule",
        (("keep_round_key_injection", "false"),),
    )
    return TransformationResult(
        derived,
        tuple((name, name) for name in inputs),
    )


def remove_key_schedule(
    primitive: Primitive,
    *,
    keep_round_key_injection: bool = True,
) -> TransformationResult:
    """Remove computed key dependencies from a primitive graph.

    Retained injections become explicit ``round_key_*`` inputs.  With
    ``keep_round_key_injection=False``, recognized zero-neutral injection
    operations are bypassed and the resulting graph has no key inputs.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> transformed = remove_key_schedule(Speck(number_of_rounds=2)).primitive
        >>> tuple(transformed.graph.input_ports)
        ('plaintext', 'round_key_0', 'round_key_1')
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("remove_key_schedule requires a Primitive")
    if not isinstance(keep_round_key_injection, bool):
        raise TypeError("keep_round_key_injection must be a boolean")
    if primitive.graph.output is None:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive has no declared output",
        )
    secret_inputs = frozenset(primitive.graph.secret_inputs)
    if not secret_inputs:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive declares no secret key input",
        )
    index = DependencyIndex(primitive)
    dependencies = _input_dependencies(primitive, index)
    if not keep_round_key_injection:
        return _rebuild_without_key_injections(primitive, index, dependencies, secret_inputs)

    boundaries = _round_key_boundaries(
        primitive,
        index,
        dependencies,
        secret_inputs,
    )
    if not boundaries:
        raise TransformationError(
            TransformationFailureReason.DISCONNECTED_DEPENDENCY,
            "no key-derived round injection reaches a data-dependent component",
        )
    slice_inputs = {
        name: primitive.graph.input(name)
        for name in primitive.graph.input_ports
        if name not in secret_inputs
    }
    for number, (source_id, positions) in enumerate(boundaries):
        slice_inputs[f"round_key_{number}"] = primitive.graph.port(source_id)[positions]
    result = slice_primitive(
        primitive,
        inputs=slice_inputs,
        family_name=f"{primitive.family_name}_without_key_schedule",
    )
    for number in range(len(boundaries)):
        name = f"round_key_{number}"
        result.primitive._input_descriptors[name] = PrimitiveInput(
            result.primitive.graph.input(name).value_type,
            role="round_key",
            visibility=InputVisibility.SECRET,
        )
    if primitive.kind in (PrimitiveKind.BLOCK_CIPHER, PrimitiveKind.TWEAKABLE_BLOCK_CIPHER):
        object.__setattr__(result.primitive, "_kind", primitive.kind)
    _record(
        result.primitive,
        primitive,
        "remove_key_schedule",
        (("keep_round_key_injection", "true"),),
    )
    return TransformationResult(
        result.primitive,
        tuple(
            (source_id, f"round_key_{number}") for number, (source_id, _) in enumerate(boundaries)
        ),
    )


def _linear_permutation(component):
    if not isinstance(component, LinearMap):
        return None
    size = len(component.matrix)
    if size != component.inputs[0].value_type.unit_count:
        return None
    mapping = []
    for row in component.matrix:
        ones = tuple(index for index, value in enumerate(row) if value == 1)
        if len(ones) != 1 or any(value not in (0, 1) for value in row):
            return None
        mapping.append(ones[0])
    return tuple(mapping) if set(mapping) == set(range(size)) else None


def inline_reorderings(primitive: Primitive) -> TransformationResult:
    """Replace exact reorder-only semantic components with graph bindings.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> source = Speck(number_of_rounds=1)
        >>> derived = inline_reorderings(source).primitive
        >>> derived.evaluate(0x6574694c, 0x1918111009080100) == source.evaluate(0x6574694c, 0x1918111009080100)
        True
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("inline_reorderings requires a Primitive")
    if primitive.graph.output is None:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive has no declared output",
        )
    index = DependencyIndex(primitive)
    required = set(index.ancestors(primitive.graph.output.source.owner_id))
    derived = Primitive(
        f"{primitive.family_name}_inlined",
        primitive.graph.input_descriptors,
        kind=primitive.kind,
        provenance=primitive.provenance,
    )
    derived.realization = primitive.realization
    ports = {name: derived.graph.input(name) for name in primitive.graph.input_ports}
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
    inlined = set()

    def remap(selection):
        return ports[selection.source.owner_id][selection.positions]

    for source_id in index.topological_ids:
        if source_id not in required or source_id in primitive.graph.input_ports:
            continue
        source = index.source(source_id)
        if source.kind is GraphSourceKind.BINDING:
            binding = binding_by_id[source_id]
            ports[source_id] = derived._add_binding(
                binding.kind,
                tuple(remap(item) for item in binding.inputs),
                binding.output_type,
                word_width=binding.word_width,
            )
            continue
        component = component_by_id[source_id]
        mapping = (
            component.mapping
            if isinstance(component, Permutation)
            else _linear_permutation(component)
        )
        if mapping is not None:
            ports[source_id] = derived._builder.view(remap(component.inputs[0])[mapping])
            inlined.add(source_id)
            continue
        if isinstance(component, Rotate):
            selection = remap(component.inputs[0])
            domain = selection.value_type.domain
            if not isinstance(domain, Word):  # pragma: no cover - component validation owns this
                raise AssertionError("Rotate has a non-Word input")
            bits = derived._builder.unpack_bits(selection)
            width = domain.width
            amount = component.amount
            bit_mapping = []
            for word in range(selection.value_type.unit_count):
                base = word * width
                for output_bit in range(width):
                    if component.direction == "left":
                        source_bit = (output_bit + amount) % width
                    else:
                        source_bit = (output_bit - amount) % width
                    bit_mapping.append(base + source_bit)
            reordered = derived._builder.view(bits[tuple(bit_mapping)])
            ports[source_id] = derived._builder.pack_bits(reordered, width)
            inlined.add(source_id)
            continue
        original_round = round_by_component[source_id]
        if original_round != active_round:
            derived_round_by_original[original_round] = derived._builder.add_round()
            active_round = original_round
        clone = copy(component)
        object.__setattr__(clone, "component_id", None)
        object.__setattr__(clone, "inputs", tuple(remap(item) for item in component.inputs))
        ports[source_id] = derived._builder.add_component(clone)

    derived._builder.set_output(remap(primitive.graph.output))
    for scope in primitive.graph.scopes:
        if not set(scope.component_ids) <= required or set(scope.component_ids) & inlined:
            continue
        instance = CompositeInstance(
            scope.path,
            scope.definition,
            tuple((name, remap(value)) for name, value in scope.input_bindings),
            tuple((name, remap(value)) for name, value in scope.output_bindings),
            tuple(ports[component_id].owner_id for component_id in scope.component_ids),
            derived,
        )
        derived._scopes[scope.path] = instance
        original_round = round_by_component[scope.component_ids[0]]
        if original_round in derived_round_by_original:
            derived_round_by_original[original_round]._append_scope(instance)
    _record(derived, primitive, "inline_reorderings", (("components", str(len(inlined))),))
    return TransformationResult(
        derived,
        tuple(
            (source_id, ports[source_id].owner_id)
            for source_id in index.topological_ids
            if source_id in ports
        ),
    )


__all__ = ["inline_reorderings", "prune_orphans", "remove_key_schedule"]
