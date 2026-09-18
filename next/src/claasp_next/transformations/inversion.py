"""Complete and partial inversion of immutable typed primitive graphs."""

from collections.abc import Mapping, Sequence
from copy import copy

from claasp_next.domains import BinaryExtensionField
from claasp_next.graph import (
    BindingKind, Component, Port, PortLike, Primitive, PrimitiveInput,
    PrimitiveKind, Selection, ValueType, as_selection,
)
from claasp_next.provenance import TransformationRecord
from claasp_next.transformations.contracts import (
    TransformationError, TransformationFailureReason, TransformationResult,
)
from claasp_next.transformations.inverse_rules import (
    ComponentInverseRegistry, DEFAULT_INVERSE_REGISTRY,
)
from claasp_next.transformations.traversal import DependencyIndex


Atom = tuple[str, int]


def _as_selections(value) -> tuple[Selection, ...]:
    if isinstance(value, (Port, Selection)):
        return (as_selection(value),)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        selections = tuple(as_selection(item) for item in value)
        if selections:
            return selections
    raise TypeError("an inversion boundary must be a port, selection, or non-empty sequence")


def _atoms(selection: Selection) -> tuple[Atom, ...]:
    return tuple((selection.source.owner_id, position) for position in selection.positions)


def _validate_boundary(primitive: Primitive, selection: Selection) -> None:
    try:
        source = primitive.port(selection.source.owner_id)
    except KeyError as error:
        raise TransformationError(
            TransformationFailureReason.DISCONNECTED_DEPENDENCY,
            "inversion boundary source is not in the primitive",
            source_ids=(selection.source.owner_id,),
        ) from error
    if source != selection.source:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "inversion boundary type does not match its graph source",
            source_ids=(selection.source.owner_id,),
        )


def _normalize_known(primitive: Primitive, known):
    if not isinstance(known, Mapping) or not known:
        raise TypeError("known inversion boundaries must be a non-empty mapping")
    descriptors = {}
    boundaries = {}
    occupied = set()
    for name, value in known.items():
        if not isinstance(name, str) or not name:
            raise ValueError("known boundary names must be non-empty strings")
        pieces = _as_selections(value)
        for piece in pieces:
            _validate_boundary(primitive, piece)
        domain = pieces[0].value_type.domain
        if any(piece.value_type.domain != domain for piece in pieces):
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "one known boundary must use one scalar domain",
                source_ids=tuple(piece.source.owner_id for piece in pieces),
            )
        piece_atoms = tuple(atom for piece in pieces for atom in _atoms(piece))
        duplicates = occupied.intersection(piece_atoms)
        if duplicates:
            raise TransformationError(
                TransformationFailureReason.MULTIPLE_PREDECESSORS,
                "one original wire is represented by multiple known boundaries",
                source_ids=tuple(sorted({source_id for source_id, _ in duplicates})),
            )
        occupied.update(piece_atoms)
        exact_input = (
            len(pieces) == 1
            and pieces[0].source.owner_id in primitive.input_ports
            and pieces[0].positions == tuple(range(pieces[0].source.value_type.unit_count))
            and name == pieces[0].source.owner_id
        )
        descriptors[name] = (
            primitive.input_descriptor(name)
            if exact_input else PrimitiveInput(ValueType(domain, (len(piece_atoms),)), role=name)
        )
        boundaries[name] = piece_atoms
    return descriptors, boundaries


def _assembled(derived: Primitive, equivalents: Mapping[Atom, Selection], atoms: tuple[Atom, ...]):
    pieces = tuple(equivalents[atom] for atom in atoms)
    groups = []
    current_source = None
    current_positions = []
    for piece in pieces:
        if piece.value_type.unit_count != 1:
            raise AssertionError("wire equivalents must be scalar selections")
        if piece.source == current_source:
            current_positions.append(piece.positions[0])
        else:
            if current_source is not None:
                groups.append(current_source[tuple(current_positions)])
            current_source = piece.source
            current_positions = [piece.positions[0]]
    if current_source is not None:
        groups.append(current_source[tuple(current_positions)])
    return as_selection(derived.join(*groups))


def _assign(equivalents: dict[Atom, Selection], atoms: tuple[Atom, ...], value: PortLike) -> bool:
    selection = as_selection(value)
    if selection.value_type.unit_count != len(atoms):
        raise AssertionError("equivalent wire width mismatch")
    changed = False
    for atom, position in zip(atoms, selection.positions):
        if atom not in equivalents:
            equivalents[atom] = selection.source[position]
            changed = True
    return changed


def _propagate_bindings(primitive, derived, equivalents):
    changed = False
    for binding in primitive.bindings:
        output_atoms = tuple((binding.binding_id, index) for index in range(binding.output_type.unit_count))
        input_atoms = tuple(atom for item in binding.inputs for atom in _atoms(item))
        if binding.kind in (BindingKind.JOIN, BindingKind.VIEW):
            for output_atom, input_atom in zip(output_atoms, input_atoms):
                if output_atom in equivalents and input_atom not in equivalents:
                    equivalents[input_atom] = equivalents[output_atom]
                    changed = True
                elif input_atom in equivalents and output_atom not in equivalents:
                    equivalents[output_atom] = equivalents[input_atom]
                    changed = True
            continue
        width = binding.word_width
        if width is None:  # pragma: no cover - graph validation owns this invariant
            raise AssertionError("conversion binding has no word width")
        if binding.kind is BindingKind.PACK_BITS:
            for index, output_atom in enumerate(output_atoms):
                group = input_atoms[index * width:(index + 1) * width]
                if output_atom in equivalents and not all(atom in equivalents for atom in group):
                    bits = derived.unpack_bits(equivalents[output_atom])
                    changed |= _assign(equivalents, group, bits)
                elif output_atom not in equivalents and all(atom in equivalents for atom in group):
                    bits = _assembled(derived, equivalents, group)
                    domain = binding.output_type.domain
                    packed = derived.pack_bits(
                        bits, width,
                        output_domain=domain if isinstance(domain, BinaryExtensionField) else None,
                    )
                    equivalents[output_atom] = packed[0]
                    changed = True
        elif binding.kind is BindingKind.UNPACK_BITS:
            for index, input_atom in enumerate(input_atoms):
                group = output_atoms[index * width:(index + 1) * width]
                if input_atom in equivalents and not all(atom in equivalents for atom in group):
                    bits = derived.unpack_bits(equivalents[input_atom])
                    changed |= _assign(equivalents, group, bits)
                elif input_atom not in equivalents and all(atom in equivalents for atom in group):
                    bits = _assembled(derived, equivalents, group)
                    domain = binding.inputs[0].value_type.domain
                    packed = derived.pack_bits(
                        bits, width,
                        output_domain=domain if isinstance(domain, BinaryExtensionField) else None,
                    )
                    equivalents[input_atom] = packed[0]
                    changed = True
    return changed


def partial_inverse(
    primitive: Primitive,
    target: PortLike,
    *,
    known: Mapping[str, PortLike | Sequence[PortLike]],
    family_name: str | None = None,
    registry: ComponentInverseRegistry = DEFAULT_INVERSE_REGISTRY,
) -> TransformationResult:
    """Recover a target wire from explicitly known graph boundaries.

    The construction is solver-free.  Known boundaries may include retained
    primitive inputs or intermediate wires, and multiple recovery paths share
    equivalent wires instead of introducing identity placeholders.

    EXAMPLES::

        >>> from claasp_next import Primitive, ValueType, Word
        >>> from claasp_next.components import Xor
        >>> graph = Primitive("xor", {"left": ValueType(Word(4), (1,)), "right": ValueType(Word(4), (1,))})
        >>> _ = graph.add_round()
        >>> mixed = graph.add_component(Xor(graph.inputs()))
        >>> graph.set_output(mixed)
        >>> recovered = partial_inverse(graph, graph.input("left"), known={"output": graph.output, "right": graph.input("right")}).primitive
        >>> recovered.evaluate(0x9, 0x3)
        10
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("partial_inverse requires a Primitive")
    if not isinstance(registry, ComponentInverseRegistry):
        raise TypeError("registry must be a ComponentInverseRegistry")
    target_selection = as_selection(target)
    _validate_boundary(primitive, target_selection)
    descriptors, boundaries = _normalize_known(primitive, known)
    derived = Primitive(
        family_name or f"{primitive.family_name}_partial_inverse",
        descriptors,
        kind=PrimitiveKind.FUNCTION,
        provenance=primitive.provenance,
    )
    derived.realization = primitive.realization
    derived.add_round()
    equivalents: dict[Atom, Selection] = {}
    for name, atoms in boundaries.items():
        _assign(equivalents, atoms, derived.input(name))

    components = tuple(primitive.components)
    relevant_sources = set(DependencyIndex(primitive).descendants(target_selection.source.owner_id))
    produced = set()
    stalled_errors = []
    target_atoms = _atoms(target_selection)
    while not all(atom in equivalents for atom in target_atoms):
        changed = _propagate_bindings(primitive, derived, equivalents)
        stalled_errors = []
        for component in components:
            component_id = component.component_id
            output_atoms = tuple((component_id, index) for index in range(component.output_type.unit_count))
            input_atoms = tuple(_atoms(item) for item in component.inputs)
            known_inputs = tuple(all(atom in equivalents for atom in atoms) for atoms in input_atoms)
            output_known = all(atom in equivalents for atom in output_atoms)

            if component_id not in produced and all(known_inputs):
                clone = copy(component)
                object.__setattr__(clone, "component_id", None)
                object.__setattr__(
                    clone, "inputs",
                    tuple(_assembled(derived, equivalents, atoms) for atoms in input_atoms),
                )
                result = derived.add_component(clone)
                _assign(equivalents, output_atoms, result)
                produced.add(component_id)
                changed = True
                continue

            if not output_known or component_id not in relevant_sources:
                continue
            unknown = tuple(index for index, available in enumerate(known_inputs) if not available)
            if len(unknown) > 1:
                stalled_errors.append(TransformationError(
                    TransformationFailureReason.MULTIPLE_PREDECESSORS,
                    "component output leaves multiple unknown predecessors",
                    source_ids=(component_id,) if component_id else (),
                ))
                continue
            if not unknown:
                continue
            recover = unknown[0]
            if any(atom in equivalents for atom in input_atoms[recover]):
                stalled_errors.append(TransformationError(
                    TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                    "only part of a component predecessor is known",
                    source_ids=(component.inputs[recover].source.owner_id,),
                ))
                continue
            auxiliaries = {
                index: _assembled(derived, equivalents, atoms)
                for index, atoms in enumerate(input_atoms) if index != recover
            }
            try:
                inverse = registry.invert(
                    component,
                    _assembled(derived, equivalents, output_atoms),
                    recover_input=recover,
                    auxiliary_inputs=auxiliaries,
                )
            except TransformationError as error:
                stalled_errors.append(error)
                continue
            result = derived.add_component(inverse)
            _assign(equivalents, input_atoms[recover], result)
            produced.add(component_id)
            changed = True
        if not changed:
            if stalled_errors:
                priorities = {
                    TransformationFailureReason.UNSUPPORTED_COMPONENT: 0,
                    TransformationFailureReason.INFORMATION_LOSS: 1,
                    TransformationFailureReason.MISSING_AUXILIARY_VALUE: 2,
                    TransformationFailureReason.MULTIPLE_PREDECESSORS: 3,
                    TransformationFailureReason.AMBIGUOUS_BOUNDARY: 4,
                }
                raise min(stalled_errors, key=lambda error: priorities.get(error.reason, 99))
            missing = tuple(sorted({source_id for source_id, position in target_atoms if (source_id, position) not in equivalents}))
            raise TransformationError(
                TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                "known boundaries do not connect to every requested target wire",
                source_ids=missing,
            )

    derived.set_output(_assembled(derived, equivalents, target_atoms))
    record = TransformationRecord(
        "partial_inverse",
        (("target", target_selection.source.owner_id), ("known", ",".join(boundaries))),
        primitive.realization_identity,
    )
    object.__setattr__(
        derived, "_transformation_provenance",
        (*primitive.transformation_provenance, record),
    )
    return TransformationResult(
        derived,
        tuple((source_id, name) for name, atoms in boundaries.items() for source_id in dict.fromkeys(atom[0] for atom in atoms)),
    )


def invert_primitive(
    primitive: Primitive,
    recover_input: str | int = 0,
    *,
    retained_inputs: Sequence[str | int] | None = None,
    output_name: str = "output",
    family_name: str | None = None,
    registry: ComponentInverseRegistry = DEFAULT_INVERSE_REGISTRY,
) -> TransformationResult:
    """Build a complete primitive inverse with retained auxiliary inputs.

    By default the first primitive input is recovered and every other input is
    retained.  The forward output becomes the inverse graph's ``output`` input.

    EXAMPLES::

        >>> from claasp_next.primitives import Speck
        >>> primitive = Speck(number_of_rounds=2)
        >>> inverse = invert_primitive(primitive).primitive
        >>> plaintext, key = 0x6574694c, 0x1918111009080100
        >>> inverse.evaluate(primitive.evaluate(plaintext, key), key) == plaintext
        True
    """

    if not isinstance(primitive, Primitive):
        raise TypeError("invert_primitive requires a Primitive")
    if primitive.output is None:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive has no declared output",
        )
    recovered = primitive.input(recover_input)
    retained = (
        tuple(port for port in primitive.inputs() if port.owner_id != recovered.owner_id)
        if retained_inputs is None else tuple(primitive.input(selector) for selector in retained_inputs)
    )
    if any(port.owner_id == recovered.owner_id for port in retained):
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "the recovered input cannot also be retained",
            source_ids=(recovered.owner_id,),
        )
    if len({port.owner_id for port in retained}) != len(retained):
        raise TransformationError(
            TransformationFailureReason.MULTIPLE_PREDECESSORS,
            "retained primitive inputs must be unique",
        )
    known = {output_name: primitive.output}
    known.update((port.owner_id, port) for port in retained)
    result = partial_inverse(
        primitive,
        recovered,
        known=known,
        family_name=family_name or f"{primitive.family_name}_inverse",
        registry=registry,
    )
    derived = result.primitive
    complete = (
        set(port.owner_id for port in retained)
        == set(primitive.input_ports) - {recovered.owner_id}
        and primitive.output.value_type == recovered.value_type
    )
    if complete and primitive.kind in (
        PrimitiveKind.BLOCK_CIPHER, PrimitiveKind.TWEAKABLE_BLOCK_CIPHER,
        PrimitiveKind.PERMUTATION,
    ):
        object.__setattr__(derived, "_kind", primitive.kind)
    record = TransformationRecord(
        "inverse",
        (("recover", recovered.owner_id), ("retained", ",".join(port.owner_id for port in retained))),
        primitive.realization_identity,
    )
    object.__setattr__(
        derived, "_transformation_provenance",
        (*primitive.transformation_provenance, record),
    )
    return TransformationResult(derived, result.sources)


__all__ = ["invert_primitive", "partial_inverse"]
