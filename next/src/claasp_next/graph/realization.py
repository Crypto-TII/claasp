"""Metadata and deterministic selection for primitive graph realizations."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class RealizationMaturity(str, Enum):
    """Describe the review status of one graph realization.

    EXAMPLES::

        >>> RealizationMaturity.LEGACY_REGRESSION.value
        'legacy_regression'
    """

    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    LEGACY_REGRESSION = "legacy_regression"


class RealizationSelectionPolicy(str, Enum):
    """Choose how multiple compatible realization graphs are resolved.

    EXAMPLES::

        >>> RealizationSelectionPolicy.PREFERRED.value
        'preferred'
    """

    PREFERRED = "preferred"
    UNIQUE = "unique"


class RealizationSelectionError(ValueError):
    """Report a realization-selection failure.

    EXAMPLES::

        >>> str(RealizationSelectionError("no match"))
        'no match'
    """


class UnsupportedRealizationError(RealizationSelectionError):
    """Report that no realization satisfies requested capabilities.

    EXAMPLES::

        >>> isinstance(UnsupportedRealizationError("missing"), RealizationSelectionError)
        True
    """


class AmbiguousRealizationError(RealizationSelectionError):
    """Report that a policy cannot choose one compatible realization.

    EXAMPLES::

        >>> isinstance(AmbiguousRealizationError("ambiguous"), RealizationSelectionError)
        True
    """


def _names(values: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError(f"{label} must be an iterable of names, not a string")
    frozen = frozenset(values)
    if any(not isinstance(item, str) or not item for item in frozen):
        raise ValueError(f"{label} entries must be non-empty strings")
    return frozen


@dataclass(frozen=True, slots=True)
class RealizationDescriptor:
    """Record stable realization capabilities, structure, and provenance.

    EXAMPLES::

        >>> descriptor = RealizationDescriptor(
        ...     "word", frozenset({"scalar"}), frozenset({"word"}), "word graph", priority=2
        ... )
        >>> (descriptor.supports({"scalar"}), descriptor.priority)
        (True, 2)
    """

    name: str
    capabilities: frozenset[str]
    structure: frozenset[str]
    description: str
    maturity: RealizationMaturity = RealizationMaturity.STABLE
    provenance: tuple[str, ...] = ()
    priority: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("a realization requires a non-empty name")
        if not isinstance(self.description, str) or not self.description:
            raise ValueError("a realization requires a non-empty description")
        object.__setattr__(self, "capabilities", _names(self.capabilities, "capabilities"))
        object.__setattr__(self, "structure", _names(self.structure, "structural features"))
        if not isinstance(self.maturity, RealizationMaturity):
            object.__setattr__(self, "maturity", RealizationMaturity(self.maturity))
        frozen_provenance = tuple(self.provenance)
        if any(not isinstance(item, str) or not item for item in frozen_provenance):
            raise ValueError("realization provenance entries must be non-empty strings")
        object.__setattr__(self, "provenance", frozen_provenance)
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise TypeError("realization priority must be an integer")

    def supports(self, requirements: Iterable[str]) -> bool:
        """Return whether all requested capabilities are declared."""

        return _names(requirements, "capability requirements") <= self.capabilities


def select_realization(
    descriptors: Iterable[RealizationDescriptor],
    requirements: Iterable[str],
    *,
    policy: RealizationSelectionPolicy | str = RealizationSelectionPolicy.PREFERRED,
    primitive_name: str = "primitive",
) -> RealizationDescriptor:
    """Select a compatible descriptor under a deterministic policy.

    EXAMPLES::

        >>> slow = RealizationDescriptor("slow", frozenset({"scalar"}), frozenset(), "slow", priority=5)
        >>> fast = RealizationDescriptor("fast", frozenset({"scalar"}), frozenset(), "fast", priority=1)
        >>> select_realization((slow, fast), {"scalar"}).name
        'fast'
    """

    requested = _names(requirements, "capability requirements")
    selected_policy = policy if isinstance(policy, RealizationSelectionPolicy) else RealizationSelectionPolicy(policy)
    matches = tuple(item for item in descriptors if item.supports(requested))
    rendered = tuple(sorted(requested))
    if not matches:
        raise UnsupportedRealizationError(
            f"no {primitive_name} realization supports capabilities {rendered}"
        )
    if selected_policy is RealizationSelectionPolicy.UNIQUE:
        if len(matches) != 1:
            names = tuple(item.name for item in matches)
            raise AmbiguousRealizationError(
                f"{primitive_name} capability request {rendered} matches {names} under unique policy"
            )
        return matches[0]
    best_priority = min(item.priority for item in matches)
    preferred = tuple(item for item in matches if item.priority == best_priority)
    if len(preferred) != 1:
        names = tuple(item.name for item in preferred)
        raise AmbiguousRealizationError(
            f"{primitive_name} capability request {rendered} has equal-priority matches {names}"
        )
    return preferred[0]


def normalize_realization_contract(reference, candidate, descriptor: RealizationDescriptor):
    """Return ``candidate`` behind ``reference``'s exact typed boundary.

    Legacy-derived graphs sometimes expose bits where the canonical authoring
    graph exposes words, or declare the same named inputs in another order.
    This adapter adds explicit conversions and clones graph components; it
    never treats an execution engine as part of the realization.

    EXAMPLES::

        >>> from claasp_next.primitives import AES
        >>> reference = AES(number_of_rounds=1)
        >>> candidate = AES(number_of_rounds=1)
        >>> normalize_realization_contract(reference, candidate, candidate.realization).family_name
        'aes'
    """

    from copy import copy

    from claasp_next.domains import BinaryExtensionField, Bit, Word
    from claasp_next.graph.port import as_selection
    from claasp_next.graph.primitive import Primitive

    if not isinstance(reference, Primitive) or not isinstance(candidate, Primitive):
        raise TypeError("realization contract normalization requires Primitive graphs")
    if reference.kind != candidate.kind:
        raise ValueError("equivalent realizations must have the same primitive kind")
    if set(reference.input_descriptors) != set(candidate.input_descriptors):
        raise ValueError("equivalent realizations must have the same named inputs")
    if reference.output is None or candidate.output is None:
        raise ValueError("equivalent realizations require declared outputs")

    def encoded_size(value_type):
        if value_type.encoded_bit_size is None:
            raise ValueError("realization boundary normalization requires fixed-width types")
        return value_type.encoded_bit_size

    for name, expected in reference.input_descriptors.items():
        actual = candidate.input_descriptor(name)
        if encoded_size(expected.value_type) != encoded_size(actual.value_type):
            raise ValueError(f"realization input {name!r} has a different encoded width")
        if expected.role != actual.role or expected.visibility != actual.visibility:
            raise ValueError(f"realization input {name!r} has different role or visibility metadata")
    if encoded_size(reference.output.value_type) != encoded_size(candidate.output.value_type):
        raise ValueError("equivalent realizations have different output widths")

    exact_inputs = tuple(reference.input_descriptors.items()) == tuple(candidate.input_descriptors.items())
    if exact_inputs and reference.output.value_type == candidate.output.value_type:
        candidate._family_name = reference.family_name
        candidate.realization = descriptor
        return candidate
    if candidate.scopes:
        raise ValueError("boundary normalization of hierarchical realizations is not supported")

    normalized = Primitive(
        reference.family_name,
        reference.input_descriptors,
        kind=reference.kind,
        provenance=reference.provenance + candidate.provenance,
    )
    normalized.realization = descriptor
    remapped = {}

    def convert(selection, target_type, component_id):
        selection = as_selection(selection)
        if selection.value_type == target_type:
            return selection
        source_domain = selection.value_type.domain
        target_domain = target_type.domain
        value = selection
        if not isinstance(source_domain, Bit):
            value = normalized.unpack_bits(value)
        if isinstance(target_domain, Bit):
            converted = value
        elif isinstance(target_domain, Word):
            converted = normalized.pack_bits(value, target_domain.width)
        elif isinstance(target_domain, BinaryExtensionField):
            converted = normalized.pack_bits(
                value, target_domain.degree, output_domain=target_domain,
            )
        else:
            raise ValueError(
                f"cannot normalize realization boundary to {type(target_domain).__name__}"
            )
        if converted.value_type != target_type:
            raise ValueError("realization boundary conversion produced the wrong typed shape")
        return converted

    candidate_rounds = candidate.rounds or ((),)
    pending_bindings = list(candidate.bindings)

    def drain_bindings():
        from claasp_next.graph.binding import BindingKind

        changed = True
        while changed:
            changed = False
            for binding in tuple(pending_bindings):
                if not all(item.source.owner_id in remapped for item in binding.inputs):
                    continue
                inputs = tuple(
                    remapped[item.source.owner_id][item.positions] for item in binding.inputs
                )
                if binding.kind is BindingKind.JOIN:
                    output = normalized.join(*inputs)
                elif binding.kind is BindingKind.VIEW:
                    output = normalized.view(inputs[0])
                elif binding.kind is BindingKind.PACK_BITS:
                    output = normalized.pack_bits(
                        inputs[0], binding.word_width,
                        output_domain=(
                            binding.output_type.domain
                            if isinstance(binding.output_type.domain, BinaryExtensionField)
                            else None
                        ),
                    )
                else:
                    output = normalized.unpack_bits(inputs[0])
                remapped[binding.binding_id] = as_selection(output)
                pending_bindings.remove(binding)
                changed = True

    for round_index, candidate_round in enumerate(candidate_rounds):
        normalized.add_round()
        if round_index == 0:
            for name, port in candidate.input_ports.items():
                remapped[name] = as_selection(convert(
                    normalized.input(name), port.value_type, f"__realization_input_{name}"
                ))
            drain_bindings()
        for component in getattr(candidate_round, "components", ()):
            drain_bindings()
            cloned = copy(component)
            object.__setattr__(cloned, "inputs", tuple(
                remapped[item.source.owner_id][item.positions] for item in component.inputs
            ))
            remapped[component.component_id] = normalized.add_component(cloned).select_all()
    drain_bindings()
    if pending_bindings:
        raise ValueError("realization contains unresolved structural bindings")

    candidate_output = remapped[candidate.output.source.owner_id][candidate.output.positions]
    normalized.set_output(convert(
        candidate_output, reference.output.value_type, "__realization_output"
    ))
    return normalized
