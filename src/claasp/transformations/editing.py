"""Immutable editor-style transformations for typed primitive graphs."""

from collections.abc import Mapping
from copy import copy
from dataclasses import replace
from itertools import groupby

from claasp.components import (
    Add,
    LinearMap,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    Xor,
)
from claasp.graph import (
    InputVisibility,
    Primitive,
    PrimitiveInput,
    PrimitiveKind,
    Selection,
    UnitArray,
    UnitArrayType,
    as_selection,
)
from claasp.graph.binding import BindingKind
from claasp.graph.composite import CompositeInstance
from claasp.provenance import TransformationRecord
from claasp.transformations._observations import _preserve_observations
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
    TransformationResult,
)
from claasp.transformations.slicing import slice_primitive
from claasp.transformations.traversal import DependencyIndex, GraphSourceKind
from claasp.unit_types import BinaryExtensionField, Bit, Word


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


def _canonical_binary_wiring(primitive, dependencies):
    """Isolate selected encoded bits before classifying key-only operands.

    Joining state and key bits does not make every later slice depend on
    both. Rebuild only when whole-binding dependency sets obscure a slice;
    repeated equivalent operand views share one new boundary.
    """
    arrays = [value.array_type for value in primitive.graph.input_arrays.values()]
    arrays += [component.output_type for component in primitive.graph.components]
    if not all(isinstance(array.unit_type, (Bit, Word, BinaryExtensionField)) for array in arrays):
        return primitive, {}
    actual = {name: frozenset((name,)) for name in primitive.graph.input_arrays}
    needed = False
    for component in primitive.graph.components:
        selected = []
        for selection in component.inputs:
            names = frozenset(
                name
                for source, _ in primitive.graph.selection_bit_sources(selection)
                for name in actual[source]
            )
            selected.append(names)
            needed |= names != dependencies[selection.source.source_id]
        actual[component.component_id] = frozenset().union(*selected)
    if not needed:
        return primitive, {}

    derived = Primitive(
        primitive.family_name,
        dict(primitive.graph.input_descriptors),
        kind=primitive.kind,
        provenance=primitive.provenance,
    )
    derived.realization = primitive.realization
    object.__setattr__(derived, "_transformation_provenance", primitive.transformation_provenance)
    sources = {name: derived.graph.input(name) for name in primitive.graph.input_arrays}
    unpacked = {}
    remapped: dict[tuple[tuple[tuple[str, int], ...], UnitArrayType], Selection] = {}
    origins = {}
    prefix = "canonical_wiring_"
    while any(name.startswith(prefix) for name in primitive._unit_arrays):
        prefix += "_"
    counter = 0

    def binding(kind, inputs, output_type, word_width=None):
        nonlocal counter
        name = f"{prefix}{counter}"
        counter += 1
        return derived._add_binding(
            kind,
            tuple(as_selection(item) for item in inputs),
            output_type,
            word_width=word_width,
            binding_id=name,
        )

    def remap(value):
        selection = as_selection(value)
        refs = primitive.graph.selection_bit_sources(selection)
        cache_key = refs, selection.array_type
        if cache_key in remapped:
            return remapped[cache_key]
        pieces = []
        for source_id, group in groupby(refs, key=lambda item: item[0]):
            source = sources[source_id]
            if isinstance(source.array_type.unit_type, Bit):
                bits = source
            else:
                if source_id not in unpacked:
                    width = source.array_type.unit_type.encoded_bit_size
                    total_width = source.array_type.encoded_bit_size
                    assert width is not None and total_width is not None
                    unpacked[source_id] = binding(
                        BindingKind.UNPACK_BITS,
                        (source,),
                        UnitArrayType(Bit(), (total_width,)),
                        width,
                    )
                bits = unpacked[source_id]
            pieces.append(bits[tuple(position for _, position in group)])
        joined = (
            pieces[0]
            if len(pieces) == 1
            else binding(BindingKind.JOIN, pieces, UnitArrayType(Bit(), (len(refs),)))
        )
        unit = selection.array_type.unit_type
        packed = (
            joined
            if isinstance(unit, Bit)
            else binding(
                BindingKind.PACK_BITS, (joined,), selection.array_type, unit.encoded_bit_size
            )
        )
        view = binding(BindingKind.VIEW, (packed,), selection.array_type)
        result = view.select_all()
        remapped[cache_key] = result
        origins[view.source_id] = selection
        return result

    rounds = {}
    for original_round in primitive.graph.rounds:
        rounds[original_round.number] = derived._builder.add_round()
        for component in original_round.components:
            cloned = copy(component)
            object.__setattr__(
                cloned, "inputs", tuple(remap(selection) for selection in component.inputs)
            )
            sources[component.component_id] = derived._builder.add_component(cloned)
    derived._builder.set_output(remap(primitive.graph.output))
    object.__setattr__(derived, "_round_count", primitive.details().number_of_rounds)

    def published(value):
        if isinstance(value, (UnitArray, Selection)):
            return remap(value)
        if isinstance(value, Mapping):
            return {name: published(item) for name, item in value.items()}
        if isinstance(value, (tuple, list)):
            return tuple(published(item) for item in value)
        return value

    for attribute in (
        "_published_intermediate_outputs",
        "_published_round_keys",
        "_published_key_schedule_states",
    ):
        if hasattr(primitive, attribute):
            setattr(derived, attribute, published(getattr(primitive, attribute)))
    for scope in primitive.graph.scopes:
        instance = CompositeInstance(
            scope.path,
            scope.definition,
            tuple((name, remap(value)) for name, value in scope.input_bindings),
            tuple((name, remap(value)) for name, value in scope.output_bindings),
            scope.component_ids,
            derived,
        )
        derived._scopes[scope.path] = instance
        if scope.component_ids:
            number = next(
                original_round.number
                for original_round in primitive.graph.rounds
                if any(
                    component.component_id == scope.component_ids[0]
                    for component in original_round.components
                )
            )
            rounds[number]._append_scope(instance)
    return derived, origins


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
            source_id = selection.source.source_id
            source_dependencies = dependencies[source_id]
            if source_dependencies and source_dependencies <= secret_inputs:
                if source_id not in positions:
                    positions[source_id] = []
                    order.append(source_id)
                for position in selection.positions:
                    if position not in positions[source_id]:
                        positions[source_id].append(position)
    return tuple((source_id, tuple(positions[source_id])) for source_id in order)


def _zero_neutral_data_inputs(component, dependencies, secret_inputs):
    data_indices = tuple(
        index
        for index, selection in enumerate(component.inputs)
        if not (
            dependencies[selection.source.source_id]
            and dependencies[selection.source.source_id] <= secret_inputs
        )
    )
    key_indices = tuple(
        index for index in range(len(component.inputs)) if index not in data_indices
    )
    if not data_indices or not key_indices:
        return None
    if isinstance(component, (Xor, Add, ModularAdd)):
        return data_indices
    if isinstance(component, ModularSubtract) and data_indices == (0,):
        return (0,)
    return None


def _rebuild_without_key_injections(primitive, index, dependencies, secret_inputs):
    injections = {}
    for component in primitive.graph.components:
        source_dependencies = dependencies[component.component_id]
        if source_dependencies <= secret_inputs:
            continue
        has_key = any(
            dependencies[item.source.source_id]
            and dependencies[item.source.source_id] <= secret_inputs
            for item in component.inputs
        )
        if not has_key:
            continue
        data_indices = _zero_neutral_data_inputs(component, dependencies, secret_inputs)
        if data_indices is None:
            raise TransformationError(
                TransformationFailureReason.UNSUPPORTED_COMPONENT,
                "key injection is not a recognized zero-neutral operation",
                source_ids=(component.component_id,),
            )
        if any(
            component.inputs[index].array_type != component.output_type for index in data_indices
        ):
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "key injection data input does not match its output type",
                source_ids=(component.component_id,),
            )
        injections[component.component_id] = tuple(
            component.inputs[index] for index in data_indices
        )

    required = set()
    visiting = [primitive.graph.output.source.source_id]
    while visiting:
        source_id = visiting.pop()
        if source_id in required:
            continue
        required.add(source_id)
        if source_id in injections:
            visiting.extend(selection.source.source_id for selection in injections[source_id])
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
    unit_arrays = {name: derived.graph.input(name) for name in inputs}
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
    retained_rounds = {}

    def remap(selection):
        try:
            return unit_arrays[selection.source.source_id][selection.positions]
        except KeyError as error:
            raise TransformationError(
                TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                "key removal left a required source unavailable",
                source_ids=(selection.source.source_id,),
            ) from error

    for source_id in index.topological_ids:
        if source_id not in required or source_id in inputs:
            continue
        if source_id in injections:
            operands = tuple(remap(selection) for selection in injections[source_id])
            if len(operands) == 1:
                unit_arrays[source_id] = operands[0]
            else:
                original_round = round_by_component[source_id]
                if original_round != active_round:
                    retained_rounds[original_round] = derived._builder.add_round()
                    active_round = original_round
                clone = copy(component_by_id[source_id])
                object.__setattr__(clone, "component_id", None)
                object.__setattr__(clone, "inputs", operands)
                unit_arrays[source_id] = derived._builder.add_component(clone)
            continue
        source = index.source(source_id)
        if source.kind is GraphSourceKind.BINDING:
            binding = binding_by_id[source_id]
            unit_arrays[source_id] = derived._add_binding(
                binding.kind,
                tuple(remap(item) for item in binding.inputs),
                binding.output_type,
                word_width=binding.word_width,
            )
        elif source.kind is GraphSourceKind.COMPONENT:
            component = component_by_id[source_id]
            original_round = round_by_component[source_id]
            if original_round != active_round:
                retained_rounds[original_round] = derived._builder.add_round()
                active_round = original_round
            clone = copy(component)
            object.__setattr__(clone, "component_id", None)
            object.__setattr__(clone, "inputs", tuple(remap(item) for item in component.inputs))
            unit_arrays[source_id] = derived._builder.add_component(clone)
    derived._builder.set_output(remap(primitive.graph.output))
    _preserve_observations(primitive, derived, unit_arrays, retained_rounds)
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
        >>> tuple(transformed.graph.input_arrays)
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
    source_primitive = primitive
    primitive, origins = _canonical_binary_wiring(primitive, dependencies)
    if primitive is not source_primitive:
        index = DependencyIndex(primitive)
        dependencies = _input_dependencies(primitive, index)
    if not keep_round_key_injection:
        result = _rebuild_without_key_injections(primitive, index, dependencies, secret_inputs)
        return replace(
            result,
            source_primitive=source_primitive,
            input_boundaries=tuple(
                (name, as_selection(source_primitive.graph.input(name)))
                for name in result.primitive.graph.input_arrays
            ),
        )

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
        for name in primitive.graph.input_arrays
        if name not in secret_inputs
    }
    for number, (source_id, positions) in enumerate(boundaries):
        slice_inputs[f"round_key_{number}"] = primitive.graph.unit_array(source_id)[positions]
    result = slice_primitive(
        primitive,
        inputs=slice_inputs,
        family_name=f"{primitive.family_name}_without_key_schedule",
    )
    result.primitive._published_round_keys = tuple(
        result.primitive.graph.input(f"round_key_{number}") for number in range(len(boundaries))
    )
    for number in range(len(boundaries)):
        name = f"round_key_{number}"
        result.primitive._input_descriptors[name] = PrimitiveInput(
            result.primitive.graph.input(name).array_type,
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
    input_boundaries = [
        (name, as_selection(source_primitive.graph.input(name)))
        for name in source_primitive.graph.input_arrays
        if name not in secret_inputs
    ]
    source_pairs = []
    for number, (source_id, positions) in enumerate(boundaries):
        original = origins.get(source_id)
        if original is None:
            original = as_selection(source_primitive.graph.unit_array(source_id))
        selected = original[positions]
        input_boundaries.append((f"round_key_{number}", selected))
        source_pairs.append((selected.source.source_id, f"round_key_{number}"))
    return TransformationResult(
        result.primitive, tuple(source_pairs), tuple(input_boundaries), source_primitive
    )


def _linear_permutation(component):
    if not isinstance(component, LinearMap):
        return None
    size = len(component.matrix)
    if size != component.inputs[0].array_type.unit_count:
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
    required = set(index.ancestors(primitive.graph.output.source.source_id))
    derived = Primitive(
        f"{primitive.family_name}_inlined",
        primitive.graph.input_descriptors,
        kind=primitive.kind,
        provenance=primitive.provenance,
    )
    derived.realization = primitive.realization
    unit_arrays = {name: derived.graph.input(name) for name in primitive.graph.input_arrays}
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
        return unit_arrays[selection.source.source_id][selection.positions]

    for source_id in index.topological_ids:
        if source_id not in required or source_id in primitive.graph.input_arrays:
            continue
        source = index.source(source_id)
        if source.kind is GraphSourceKind.BINDING:
            binding = binding_by_id[source_id]
            unit_arrays[source_id] = derived._add_binding(
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
            unit_arrays[source_id] = derived._builder.view(remap(component.inputs[0])[mapping])
            inlined.add(source_id)
            continue
        if isinstance(component, Rotate):
            selection = remap(component.inputs[0])
            unit_type = selection.array_type.unit_type
            if not isinstance(unit_type, Word):  # pragma: no cover - component validation owns this
                raise AssertionError("Rotate has a non-Word input")
            bits = derived._builder.unpack_bits(selection)
            width = unit_type.width
            amount = component.amount
            bit_mapping = []
            for word in range(selection.array_type.unit_count):
                base = word * width
                for output_bit in range(width):
                    if component.direction == "left":
                        source_bit = (output_bit + amount) % width
                    else:
                        source_bit = (output_bit - amount) % width
                    bit_mapping.append(base + source_bit)
            reordered = derived._builder.view(bits[tuple(bit_mapping)])
            unit_arrays[source_id] = derived._builder.pack_bits(reordered, width)
            inlined.add(source_id)
            continue
        original_round = round_by_component[source_id]
        if original_round != active_round:
            derived_round_by_original[original_round] = derived._builder.add_round()
            active_round = original_round
        clone = copy(component)
        object.__setattr__(clone, "component_id", None)
        object.__setattr__(clone, "inputs", tuple(remap(item) for item in component.inputs))
        unit_arrays[source_id] = derived._builder.add_component(clone)

    derived._builder.set_output(remap(primitive.graph.output))
    for scope in primitive.graph.scopes:
        if not set(scope.component_ids) <= required or set(scope.component_ids) & inlined:
            continue
        instance = CompositeInstance(
            scope.path,
            scope.definition,
            tuple((name, remap(value)) for name, value in scope.input_bindings),
            tuple((name, remap(value)) for name, value in scope.output_bindings),
            tuple(unit_arrays[component_id].source_id for component_id in scope.component_ids),
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
            (source_id, unit_arrays[source_id].source_id)
            for source_id in index.topological_ids
            if source_id in unit_arrays
        ),
    )


__all__ = ["inline_reorderings", "prune_orphans", "remove_key_schedule"]
