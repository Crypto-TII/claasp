"""Complete and partial inversion of immutable typed primitive graphs."""

from collections import deque
from collections.abc import Mapping, Sequence
from copy import copy

from claasp_next.components import Add, LinearMap, Rotate, Xor
from claasp_next.domains import BinaryExtensionField, Bit, Word
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
from claasp_next.transformations.inverse_equivalents import (
    direct_inversion_equivalent, inversion_equivalent,
)
from claasp_next.transformations.traversal import DependencyIndex


Atom = tuple[str, int]


def _qualified_primitive_type(primitive):
    return f"{type(primitive).__module__}.{type(primitive).__qualname__}"


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


def _assign(
    equivalents: dict[Atom, Selection],
    atoms: tuple[Atom, ...],
    value: PortLike,
    *,
    changed_atoms: list[Atom] | None = None,
) -> bool:
    selection = as_selection(value)
    if selection.value_type.unit_count != len(atoms):
        raise AssertionError("equivalent wire width mismatch")
    changed = False
    for atom, position in zip(atoms, selection.positions):
        if atom not in equivalents:
            equivalents[atom] = selection.source[position]
            if changed_atoms is not None:
                changed_atoms.append(atom)
            changed = True
    return changed


def _propagate_binding(binding, derived, equivalents, *, changed_atoms=None):
    changed = False
    output_atoms = tuple(
        (binding.binding_id, index) for index in range(binding.output_type.unit_count)
    )
    input_atoms = tuple(atom for item in binding.inputs for atom in _atoms(item))
    if binding.kind in (BindingKind.JOIN, BindingKind.VIEW):
        for output_atom, input_atom in zip(output_atoms, input_atoms):
            if output_atom in equivalents and input_atom not in equivalents:
                equivalents[input_atom] = equivalents[output_atom]
                if changed_atoms is not None:
                    changed_atoms.append(input_atom)
                changed = True
            elif input_atom in equivalents and output_atom not in equivalents:
                equivalents[output_atom] = equivalents[input_atom]
                if changed_atoms is not None:
                    changed_atoms.append(output_atom)
                changed = True
        return changed
    width = binding.word_width
    if width is None:  # pragma: no cover - graph validation owns this invariant
        raise AssertionError("conversion binding has no word width")
    if binding.kind is BindingKind.PACK_BITS:
        for index, output_atom in enumerate(output_atoms):
            group = input_atoms[index * width:(index + 1) * width]
            if output_atom in equivalents and not all(atom in equivalents for atom in group):
                bits = derived.unpack_bits(equivalents[output_atom])
                changed |= _assign(equivalents, group, bits, changed_atoms=changed_atoms)
            elif output_atom not in equivalents and all(atom in equivalents for atom in group):
                bits = _assembled(derived, equivalents, group)
                domain = binding.output_type.domain
                packed = derived.pack_bits(
                    bits, width,
                    output_domain=domain if isinstance(domain, BinaryExtensionField) else None,
                )
                equivalents[output_atom] = packed[0]
                if changed_atoms is not None:
                    changed_atoms.append(output_atom)
                changed = True
    elif binding.kind is BindingKind.UNPACK_BITS:
        for index, input_atom in enumerate(input_atoms):
            group = output_atoms[index * width:(index + 1) * width]
            if input_atom in equivalents and not all(atom in equivalents for atom in group):
                bits = derived.unpack_bits(equivalents[input_atom])
                changed |= _assign(equivalents, group, bits, changed_atoms=changed_atoms)
            elif input_atom not in equivalents and all(atom in equivalents for atom in group):
                bits = _assembled(derived, equivalents, group)
                domain = binding.inputs[0].value_type.domain
                packed = derived.pack_bits(
                    bits, width,
                    output_domain=domain if isinstance(domain, BinaryExtensionField) else None,
                )
                equivalents[input_atom] = packed[0]
                if changed_atoms is not None:
                    changed_atoms.append(input_atom)
                changed = True
    return changed


def _propagate_bindings(primitive, derived, equivalents):
    changed = False
    for binding in primitive.bindings:
        changed |= _propagate_binding(binding, derived, equivalents)
    return changed


def _recover_xor_region(
    primitive, components, derived, equivalents, bit_cache, region_cache,
):
    """Recover units isolated by exact bit-level elimination of XOR regions."""

    def width(domain):
        if isinstance(domain, Bit):
            return 1
        if isinstance(domain, Word):
            return domain.width
        if isinstance(domain, BinaryExtensionField):
            return domain.degree
        return None

    def virtual_bits(selection):
        domain_width = width(selection.value_type.domain)
        if domain_width is None:
            return ()
        return tuple(
            (selection.source.owner_id, position, bit)
            for position in selection.positions for bit in range(domain_width)
        )

    if "groups" not in region_cache:
        raw_equations = []

        def add_equation(*variables):
            coefficients = set()
            for variable in variables:
                if variable in coefficients:
                    coefficients.remove(variable)
                else:
                    coefficients.add(variable)
            if coefficients:
                raw_equations.append(frozenset(coefficients))

        for binding in primitive.bindings:
            output = primitive.port(binding.binding_id).select_all()
            output_bits = virtual_bits(output)
            input_bits = tuple(
                bit for selection in binding.inputs for bit in virtual_bits(selection)
            )
            if len(output_bits) == len(input_bits):
                for output_bit, input_bit in zip(output_bits, input_bits):
                    add_equation(output_bit, input_bit)

        for component in components:
            output = primitive.port(component.component_id).select_all()
            output_bits = virtual_bits(output)
            input_bits = tuple(virtual_bits(item) for item in component.inputs)
            if type(component) is Xor or (
                type(component) is Add
                and isinstance(component.output_type.domain, (Bit, BinaryExtensionField))
            ):
                if any(len(bits) != len(output_bits) for bits in input_bits):
                    continue  # pragma: no cover - component validation owns this
                for index, output_bit in enumerate(output_bits):
                    add_equation(output_bit, *(bits[index] for bits in input_bits))
            elif type(component) is Rotate:
                domain_width = component.output_type.domain.width
                amount = component.amount
                for unit in range(component.output_type.unit_count):
                    for bit in range(domain_width):
                        input_bit = (
                            (bit + amount) % domain_width
                            if component.direction == "left"
                            else (bit - amount) % domain_width
                        )
                        add_equation(
                            output_bits[unit * domain_width + bit],
                            input_bits[0][unit * domain_width + input_bit],
                        )
            elif type(component) is LinearMap and isinstance(component.output_type.domain, Bit):
                for output_bit, row in zip(output_bits, component.matrix):
                    add_equation(
                        output_bit,
                        *(input_bit for input_bit, coefficient in zip(input_bits[0], row) if coefficient),
                    )

        parents = {}

        def find(variable):
            parents.setdefault(variable, variable)
            while parents[variable] != variable:
                parents[variable] = parents[parents[variable]]
                variable = parents[variable]
            return variable

        def union(left, right):
            left, right = find(left), find(right)
            if left != right:
                parents[right] = left

        for coefficients in raw_equations:
            first = next(iter(coefficients))
            for variable in coefficients:
                union(first, variable)
        raw_groups = {}
        for coefficients in raw_equations:
            raw_groups.setdefault(find(next(iter(coefficients))), []).append(coefficients)
        region_cache["groups"] = tuple(tuple(group) for group in raw_groups.values())

    def known_bits(atom):
        if atom not in equivalents:
            return None
        if atom in bit_cache:
            return bit_cache[atom]
        selection = equivalents[atom]
        domain = selection.value_type.domain
        if isinstance(domain, Bit):
            bits = (selection,)
        elif isinstance(domain, (Word, BinaryExtensionField)):
            unpacked = derived.unpack_bits(selection)
            bits = tuple(unpacked[index] for index in range(unpacked.value_type.unit_count))
        else:
            return None
        bit_cache[atom] = bits
        return bits

    known = {}
    for atom in equivalents:
        bits = known_bits(atom)
        if bits is None:
            continue
        for bit, selection in enumerate(bits):
            known[(atom[0], atom[1], bit)] = (
                selection.source.owner_id, selection.positions[0],
            )

    solved = {}
    for raw_group in region_cache["groups"]:
        group = []
        for raw_coefficients in raw_group:
            coefficients = set(raw_coefficients)
            right_hand_side = set()
            for variable in tuple(coefficients):
                token = known.get(variable)
                if token is None:
                    continue
                coefficients.remove(variable)
                if token in right_hand_side:
                    right_hand_side.remove(token)
                else:
                    right_hand_side.add(token)
            if coefficients:
                group.append((coefficients, right_hand_side))
        if not group:
            continue
        if not any(right_hand_side for _, right_hand_side in group):
            continue
        variables = tuple(sorted({
            variable for coefficients, _ in group for variable in coefficients
        }))
        tokens = tuple(sorted({
            token for _, right_hand_side in group for token in right_hand_side
        }))
        variable_indexes = {variable: index for index, variable in enumerate(variables)}
        token_indexes = {token: index for index, token in enumerate(tokens)}
        basis = {}
        for coefficients, right_hand_side in group:
            coefficient_bits = sum(1 << variable_indexes[item] for item in coefficients)
            right_hand_side_bits = sum(1 << token_indexes[item] for item in right_hand_side)
            while coefficient_bits:
                pivot_bit = coefficient_bits & -coefficient_bits
                pivot = pivot_bit.bit_length() - 1
                if pivot not in basis:
                    basis[pivot] = [coefficient_bits, right_hand_side_bits]
                    break
                other_coefficients, other_right_hand_side = basis[pivot]
                coefficient_bits ^= other_coefficients
                right_hand_side_bits ^= other_right_hand_side
        for pivot in sorted(basis, reverse=True):
            pivot_coefficients, pivot_right_hand_side = basis[pivot]
            for other_pivot, (coefficients, right_hand_side) in basis.items():
                if other_pivot != pivot and coefficients & (1 << pivot):
                    basis[other_pivot][0] ^= pivot_coefficients
                    basis[other_pivot][1] ^= pivot_right_hand_side
        for coefficients, right_hand_side in basis.values():
            if coefficients.bit_count() == 1 and right_hand_side:
                variable = variables[(coefficients & -coefficients).bit_length() - 1]
                solved[variable] = {
                    tokens[index]
                    for index in range(len(tokens))
                    if right_hand_side & (1 << index)
                }

    solved_units = {}
    for (source_id, position, bit), expression in solved.items():
        solved_units.setdefault((source_id, position), {})[bit] = expression

    changed_atoms = []
    for atom, expressions in solved_units.items():
        if atom in equivalents:
            continue
        port = primitive.port(atom[0])
        domain_width = width(port.value_type.domain)
        if domain_width is None or set(expressions) != set(range(domain_width)):
            continue
        bits = []
        for bit in range(domain_width):
            selections = tuple(
                derived.port(source_id)[position]
                for source_id, position in sorted(expressions[bit])
            )
            bits.append(
                selections[0] if len(selections) == 1
                else derived.add_component(Add(selections))
            )
        if isinstance(port.value_type.domain, Bit):
            value = bits[0]
        else:
            value = derived.pack_bits(
                derived.join(*bits), domain_width,
                output_domain=(
                    port.value_type.domain
                    if isinstance(port.value_type.domain, BinaryExtensionField)
                    else None
                ),
            )
        _assign(equivalents, (atom,), value, changed_atoms=changed_atoms)
    return changed_atoms


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
    bit_cache = {}
    region_cache = {}
    for name, atoms in boundaries.items():
        _assign(equivalents, atoms, derived.input(name))

    components = tuple(primitive.components)
    bindings_to_process = tuple(primitive.bindings)
    relevant_sources = set(DependencyIndex(primitive).descendants(target_selection.source.owner_id))
    produced = set()
    stalled_errors = {}
    target_atoms = _atoms(target_selection)
    operations = (
        *(("binding", index) for index in range(len(bindings_to_process))),
        *(("component", index) for index in range(len(components))),
    )
    watchers: dict[Atom, list[tuple[str, int]]] = {}
    for operation in operations:
        operation_kind, operation_index = operation
        if operation_kind == "binding":
            binding = bindings_to_process[operation_index]
            watched_atoms = (
                *((binding.binding_id, index) for index in range(binding.output_type.unit_count)),
                *(atom for item in binding.inputs for atom in _atoms(item)),
            )
        else:
            component = components[operation_index]
            watched_atoms = (
                *((component.component_id, index) for index in range(component.output_type.unit_count)),
                *(atom for item in component.inputs for atom in _atoms(item)),
            )
        for atom in watched_atoms:
            watchers.setdefault(atom, []).append(operation)

    queue = deque(operations)
    queued = set(operations)

    def schedule(changed_atoms):
        for atom in changed_atoms:
            for operation in watchers.get(atom, ()):
                if operation not in queued:
                    queue.append(operation)
                    queued.add(operation)

    while not all(atom in equivalents for atom in target_atoms):
        if not queue:
            changed_atoms = _recover_xor_region(
                primitive, components, derived, equivalents, bit_cache, region_cache,
            )
            if not changed_atoms:
                break
            schedule(changed_atoms)
            continue
        operation_kind, operation_index = queue.popleft()
        queued.remove((operation_kind, operation_index))
        changed_atoms = []
        if operation_kind == "binding":
            _propagate_binding(
                bindings_to_process[operation_index],
                derived,
                equivalents,
                changed_atoms=changed_atoms,
            )
            schedule(changed_atoms)
            continue

        component = components[operation_index]
        component_id = component.component_id
        output_atoms = tuple(
            (component_id, index) for index in range(component.output_type.unit_count)
        )
        input_atoms = tuple(_atoms(item) for item in component.inputs)
        known_inputs = tuple(all(atom in equivalents for atom in atoms) for atoms in input_atoms)
        output_known = all(atom in equivalents for atom in output_atoms)
        stalled_errors.pop(operation_index, None)

        if component_id not in produced and all(known_inputs):
            clone = copy(component)
            object.__setattr__(clone, "component_id", None)
            object.__setattr__(
                clone, "inputs",
                tuple(_assembled(derived, equivalents, atoms) for atoms in input_atoms),
            )
            result = derived.add_component(clone)
            _assign(equivalents, output_atoms, result, changed_atoms=changed_atoms)
            produced.add(component_id)
            schedule(changed_atoms)
            continue

        if not output_known or component_id not in relevant_sources:
            continue
        unknown = tuple(index for index, available in enumerate(known_inputs) if not available)
        if len(unknown) > 1:
            stalled_errors[operation_index] = TransformationError(
                TransformationFailureReason.MULTIPLE_PREDECESSORS,
                "component output leaves multiple unknown predecessors",
                source_ids=(component_id,) if component_id else (),
            )
            continue
        if not unknown:
            continue
        recover = unknown[0]
        if any(atom in equivalents for atom in input_atoms[recover]):
            stalled_errors[operation_index] = TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "only part of a component predecessor is known",
                source_ids=(component.inputs[recover].source.owner_id,),
            )
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
            stalled_errors[operation_index] = error
            continue
        result = derived.add_component(inverse)
        _assign(
            equivalents,
            input_atoms[recover],
            result,
            changed_atoms=changed_atoms,
        )
        produced.add(component_id)
        schedule(changed_atoms)

    if not all(atom in equivalents for atom in target_atoms):
        if stalled_errors:
            priorities = {
                TransformationFailureReason.UNSUPPORTED_COMPONENT: 0,
                TransformationFailureReason.INFORMATION_LOSS: 1,
                TransformationFailureReason.MISSING_AUXILIARY_VALUE: 2,
                TransformationFailureReason.MULTIPLE_PREDECESSORS: 3,
                TransformationFailureReason.AMBIGUOUS_BOUNDARY: 4,
            }
            raise min(
                stalled_errors.values(),
                key=lambda error: priorities.get(error.reason, 99),
            )
        missing = tuple(sorted({
            source_id for source_id, position in target_atoms
            if (source_id, position) not in equivalents
        }))
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
    if not primitive.input_ports:
        raise TransformationError(
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "primitive has no input to recover",
        )
    source_recovered = primitive.input(recover_input)
    if source_recovered.owner_id == "plaintext" and retained_inputs is None:
        direct, direct_contract = direct_inversion_equivalent(primitive, output_name)
        if direct is not None:
            direct.realization = primitive.realization
            equivalent_record = TransformationRecord(
                "inverse_equivalent",
                (("source", _qualified_primitive_type(primitive)),
                 ("replacement", direct_contract[0])),
                primitive.realization_identity,
            )
            inverse_record = TransformationRecord(
                "inverse",
                (("recover", source_recovered.owner_id),
                 ("retained", ",".join(
                     port.owner_id for port in primitive.inputs()
                     if port.owner_id != source_recovered.owner_id
                 ))),
                primitive.realization_identity,
            )
            object.__setattr__(
                direct, "_transformation_provenance",
                (*primitive.transformation_provenance, equivalent_record, inverse_record),
            )
            return TransformationResult(
                direct,
                ((primitive.output.source.owner_id, output_name),
                 *((port.owner_id, port.owner_id) for port in primitive.inputs()
                   if port.owner_id != source_recovered.owner_id)),
            )
    working, equivalent_contract = inversion_equivalent(primitive)
    if working is None:
        working = primitive
    recovered = working.input(source_recovered.owner_id)
    retained = (
        tuple(port for port in working.inputs() if port.owner_id != recovered.owner_id)
        if retained_inputs is None else tuple(
            working.input(primitive.input(selector).owner_id) for selector in retained_inputs
        )
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
    known = {output_name: working.output}
    known.update((port.owner_id, port) for port in retained)
    result = partial_inverse(
        working,
        recovered,
        known=known,
        family_name=family_name or f"{primitive.family_name}_inverse",
        registry=registry,
    )
    derived = result.primitive
    complete = (
        set(port.owner_id for port in retained)
        == set(working.input_ports) - {recovered.owner_id}
        and working.output.value_type == recovered.value_type
    )
    if complete and primitive.kind in (
        PrimitiveKind.BLOCK_CIPHER, PrimitiveKind.TWEAKABLE_BLOCK_CIPHER,
        PrimitiveKind.PERMUTATION,
    ):
        object.__setattr__(derived, "_kind", primitive.kind)
    derived.realization = primitive.realization
    record = TransformationRecord(
        "inverse",
        (("recover", recovered.owner_id), ("retained", ",".join(port.owner_id for port in retained))),
        primitive.realization_identity,
    )
    object.__setattr__(
        derived, "_transformation_provenance",
        (
            *primitive.transformation_provenance,
            *(() if equivalent_contract is None else (TransformationRecord(
                "inverse_equivalent",
                (
                    ("source", equivalent_contract.source_type),
                    ("replacement", equivalent_contract.replacement_type),
                ),
                primitive.realization_identity,
            ),)),
            record,
        ),
    )
    return TransformationResult(derived, result.sources)


__all__ = ["invert_primitive", "partial_inverse"]
