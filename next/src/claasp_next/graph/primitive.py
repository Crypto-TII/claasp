"""Validated typed primitive graph."""

import re
from collections.abc import Iterable, Mapping, Sequence
from copy import copy
from types import MappingProxyType

from claasp_next.graph.binding import BindingKind, ValueBinding
from claasp_next.graph.component import Component
from claasp_next.graph.metadata import (
    InputVisibility,
    PrimitiveInput,
    PrimitiveKind,
    infer_primitive_kind,
)
from claasp_next.graph.port import Port, PortLike, Selection, as_selection
from claasp_next.graph.realization import (
    RealizationDescriptor,
    RealizationMaturity,
    RealizationSelectionPolicy,
    UnsupportedRealizationError,
    normalize_realization_contract,
    select_realization,
)
from claasp_next.graph.round import Round
from claasp_next.graph.value_type import ValueType


class Primitive:
    """Build a validated round-oriented directed acyclic graph.

    A primitive owns typed input ports, immutable component descriptions, and
    an explicit output binding. Components are evaluated by representations;
    adding one here only authors graph structure.

    EXAMPLES::

        >>> from claasp_next import Primitive, ValueType, Word
        >>> from claasp_next.components import Xor
        >>> nibble = ValueType(Word(4), (1,))
        >>> primitive = Primitive("xor_nibbles", {"left": nibble, "right": nibble})
        >>> primitive.add_round()
        Round(number=0)
        >>> output = primitive.add_component(Xor(primitive.inputs()))
        >>> primitive.set_output(output)
        >>> primitive.evaluate(0b1010, 0b0011)
        9
        >>> (primitive.family_name, len(primitive.rounds), len(primitive.components))
        ('xor_nibbles', 1, 1)
    """

    REALIZATIONS: tuple[RealizationDescriptor, ...] = ()
    REALIZATION_BUILDERS: Mapping[str, object] = MappingProxyType({})

    @staticmethod
    def select_configuration(configurations, **parameters):
        """Return the unique standard configuration matching ``parameters``."""

        matches = [
            configuration
            for configuration in configurations
            if all(configuration.get(name) == value for name, value in parameters.items())
        ]
        if len(matches) != 1:
            rendered = ", ".join(f"{name}={value}" for name, value in parameters.items())
            raise ValueError(f"unsupported primitive configuration: {rendered}")
        return matches[0]

    @staticmethod
    def validate_number_of_rounds(value, *, default: int, maximum: int, name: str) -> int:
        """Resolve and validate a positive, optionally reduced round count."""

        rounds = default if value is None else value
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if not 1 <= rounds <= maximum:
            raise ValueError(f"{name} requires between 1 and {maximum} rounds")
        return rounds

    @staticmethod
    def validate_positive_integer(value, *, name: str) -> int:
        """Validate a positive integer authoring parameter."""

        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    def __init__(
        self,
        family_name: str,
        inputs: Mapping[str, ValueType | PrimitiveInput],
        *,
        kind: PrimitiveKind | str | None = None,
        provenance: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if not isinstance(family_name, str):
            raise TypeError("family_name must be a string")
        if not family_name:
            raise ValueError("family_name must not be empty")
        if not isinstance(inputs, Mapping):
            raise TypeError("inputs must be a mapping from names to ValueType objects")
        ports: dict[str, Port] = {}
        descriptors: dict[str, PrimitiveInput] = {}
        for name, supplied in inputs.items():
            if not isinstance(name, str):
                raise TypeError("input names must be strings")
            if not name:
                raise ValueError("input names must not be empty")
            if isinstance(supplied, PrimitiveInput):
                descriptor = supplied
            elif isinstance(supplied, ValueType):
                visibility = (
                    InputVisibility.SECRET
                    if name in {"key", "secret", "secret_key"}
                    else InputVisibility.PUBLIC
                )
                descriptor = PrimitiveInput(supplied, role=name, visibility=visibility)
            else:
                raise TypeError(f"input {name!r} must have a ValueType or PrimitiveInput")
            descriptors[name] = descriptor
            ports[name] = Port(name, descriptor.value_type)

        if kind is None:
            kind = infer_primitive_kind(descriptors)
        elif not isinstance(kind, PrimitiveKind):
            kind = PrimitiveKind(kind)

        self._family_name = family_name
        self._kind = kind
        self._provenance = tuple(provenance)
        self._transformation_provenance = ()
        self._input_descriptors = descriptors
        self._input_ports = ports
        self._ports = dict(ports)
        self._rounds: list[Round] = []
        self._components: dict[str, Component] = {}
        self._bindings: dict[str, ValueBinding] = {}
        self._scopes: dict[str, object] = {}
        self._output: Selection | None = None
        if not hasattr(self, "realization"):
            self.realization = self.available_realizations()[0]

    @staticmethod
    def _default_realization() -> RealizationDescriptor:
        return RealizationDescriptor(
            "default",
            frozenset(("scalar_evaluation", "batch_evaluation")),
            frozenset(("typed_graph",)),
            "the primitive's canonical typed graph",
            RealizationMaturity.STABLE,
            ("native CLAASP v5 source",),
            0,
        )

    @property
    def family_name(self) -> str:
        """Return the stable mathematical family name."""

        return self._family_name

    @property
    def provenance(self) -> tuple[tuple[str, str], ...]:
        """Stable identity and derivation metadata for this graph."""

        return self._provenance

    @property
    def transformation_provenance(self) -> tuple[object, ...]:
        """Immutable graph derivations, distinct from realization and execution.

        EXAMPLES::

            >>> from claasp_next.primitives import Speck
            >>> Speck(number_of_rounds=1).transformation_provenance
            ()
        """

        return self._transformation_provenance

    @property
    def realization_identity(self) -> str:
        """Return the stable primitive-qualified identity of this graph."""

        return f"{self.family_name}:{self.realization.name}"

    @classmethod
    def available_realizations(cls) -> tuple[RealizationDescriptor, ...]:
        """Return declared realizations in stable preference order."""

        return tuple(cls.REALIZATIONS) or (cls._default_realization(),)

    @classmethod
    def realization_descriptor(cls, name: str) -> RealizationDescriptor:
        """Resolve an explicitly named realization or fail clearly."""

        matches = tuple(item for item in cls.available_realizations() if item.name == name)
        if len(matches) != 1:
            available = tuple(item.name for item in cls.available_realizations())
            raise UnsupportedRealizationError(
                f"{cls.__name__} realization {name!r} is unavailable; choose one of {available}"
            )
        return matches[0]

    @classmethod
    def realize(cls, name: str = "default", **parameters) -> "Primitive":
        """Construct an explicitly named graph realization."""

        descriptor = cls.realization_descriptor(name)
        builder = cls.REALIZATION_BUILDERS.get(name)
        if builder is None:
            if name not in {"default", cls.available_realizations()[0].name}:
                raise UnsupportedRealizationError(
                    f"{cls.__name__} realization {name!r} has no registered graph builder"
                )
            primitive = cls(**parameters)
        else:
            candidate = builder(**parameters)
            reference = cls(**parameters)
            primitive = normalize_realization_contract(reference, candidate, descriptor)
        if not isinstance(primitive, Primitive):
            raise TypeError("a realization builder must return a Primitive")
        primitive.realization = descriptor
        return primitive

    @classmethod
    def for_capabilities(
        cls,
        requirements,
        *,
        policy: RealizationSelectionPolicy | str = RealizationSelectionPolicy.PREFERRED,
        **parameters,
    ) -> "Primitive":
        """Construct the deterministic realization satisfying a task request."""

        descriptor = select_realization(
            cls.available_realizations(),
            requirements,
            policy=policy,
            primitive_name=cls.__name__,
        )
        return cls.realize(descriptor.name, **parameters)

    @property
    def kind(self) -> PrimitiveKind:
        """Mathematical interface category of this primitive."""

        return self._kind

    @property
    def input_descriptors(self) -> Mapping[str, PrimitiveInput]:
        """Typed roles and default visibility for primitive inputs."""

        return dict(self._input_descriptors)

    @property
    def secret_inputs(self) -> tuple[str, ...]:
        """Return secret input names in declaration order."""

        return tuple(name for name, item in self._input_descriptors.items() if item.is_secret)

    def input_descriptor(self, name: str) -> PrimitiveInput:
        """Return the typed role and visibility descriptor for one input."""

        try:
            return self._input_descriptors[name]
        except KeyError as error:
            raise KeyError(f"primitive input {name!r} does not exist") from error

    def with_input_visibility(self, **overrides: InputVisibility | str) -> "Primitive":
        """Return the same graph with study-specific input visibility metadata."""

        unexpected = set(overrides) - set(self._input_descriptors)
        if unexpected:
            raise KeyError(f"primitive inputs do not exist: {sorted(unexpected)}")
        derived = copy(self)
        derived._input_descriptors = {
            name: descriptor.with_visibility(overrides.get(name, descriptor.visibility))
            for name, descriptor in self._input_descriptors.items()
        }
        return derived

    @property
    def input_ports(self) -> Mapping[str, Port]:
        """Name-to-port mapping for representations and other graph consumers."""

        return dict(self._input_ports)

    def inputs(self, *selectors: str | int) -> Sequence[Port]:
        """Return input ports in declaration or explicitly requested order.

        With no selectors, all inputs are returned in declaration order. Names
        are preferable in specification-oriented code; zero-based positions
        are useful to generic primitive builders.
        """

        if not selectors:
            return tuple(self._input_ports.values())
        return tuple(self.input(selector) for selector in selectors)

    @property
    def rounds(self) -> tuple[Round, ...]:
        """Return authored rounds as an immutable ordered tuple."""

        return tuple(self._rounds)

    def set_round_keys(self, round_keys: Iterable[object]) -> Sequence[object]:
        """Publish round keys without exposing their storage representation."""

        self.round_keys = tuple(round_keys)
        return self.round_keys

    def add_round_key(self, round_key: object) -> object:
        """Publish one round key in authoring order."""

        self.round_keys = (*getattr(self, "round_keys", ()), round_key)
        return round_key

    def set_round_states(self, round_states: Iterable[object]) -> Sequence[object]:
        """Publish round states without exposing their storage representation."""

        self.round_states = tuple(round_states)
        return self.round_states

    def add_round_state(self, *values: object, **boundaries: object) -> object:
        """Publish one positional or named round-state observation."""

        if values and boundaries:
            raise ValueError("round state must be positional or named, not both")
        if boundaries:
            state: object = MappingProxyType(dict(boundaries))
        elif len(values) == 1:
            state = values[0]
        elif values:
            state = tuple(values)
        else:
            raise ValueError("round state must contain at least one value")
        self.round_states = (*getattr(self, "round_states", ()), state)
        return state

    def set_key_schedule_states(self, states: Iterable[object]) -> Sequence[object]:
        """Publish key-schedule states without exposing their storage representation."""

        self.key_schedule_states = tuple(states)
        return self.key_schedule_states

    def add_key_schedule_state(self, *values: object) -> object:
        """Publish one key-schedule state in authoring order."""

        if not values:
            raise ValueError("key-schedule state must contain at least one value")
        state = values[0] if len(values) == 1 else tuple(values)
        self.key_schedule_states = (*getattr(self, "key_schedule_states", ()), state)
        return state

    def set_round_operations(self, operations: Iterable[object]) -> Sequence[object]:
        """Publish round-operation landmarks without exposing their storage representation."""

        self.round_operations = tuple(operations)
        return self.round_operations

    def add_round_operations(self, **operations: object) -> Mapping[str, object]:
        """Publish named operation landmarks for one round."""

        if not operations:
            raise ValueError("round operations must not be empty")
        observation = MappingProxyType(dict(operations))
        self.round_operations = (*getattr(self, "round_operations", ()), observation)
        return observation

    @property
    def components(self) -> tuple[Component, ...]:
        """Return semantic components in deterministic graph order."""

        return tuple(self._components.values())

    @property
    def bindings(self) -> tuple[ValueBinding, ...]:
        """Return structural wiring values in construction order."""

        return tuple(self._bindings.values())

    @property
    def scopes(self) -> tuple[object, ...]:
        """Composite instances in deterministic path order."""

        return tuple(self._scopes.values())

    @property
    def output(self) -> Selection | None:
        """Return the selected graph output, or ``None`` before binding it."""

        return self._output

    def input(self, selector: str | int) -> Port:
        """Return one input port by name or zero-based declaration position."""

        if isinstance(selector, str):
            try:
                return self._input_ports[selector]
            except KeyError as error:
                raise KeyError(f"primitive input {selector!r} does not exist") from error
        if isinstance(selector, bool) or not isinstance(selector, int):
            raise TypeError("primitive input selector must be a name or integer position")
        if selector < 0 or selector >= len(self._input_ports):
            raise IndexError(f"primitive input position {selector} is out of range")
        return tuple(self._input_ports.values())[selector]

    def port(self, owner_id: str) -> Port:
        """Resolve an input, component, or binding output port by identity."""

        try:
            return self._ports[owner_id]
        except KeyError as error:
            raise KeyError(f"graph source {owner_id!r} does not exist") from error

    def component(self, component_id: str) -> Component:
        """Resolve a semantic component by its deterministic identifier."""

        try:
            return self._components[component_id]
        except KeyError as error:
            raise KeyError(f"component {component_id!r} does not exist") from error

    def scope(self, path: str):
        """Return a composite instance by its deterministic hierarchical path."""

        try:
            return self._scopes[path]
        except KeyError as error:
            raise KeyError(f"composite scope {path!r} does not exist") from error

    def add_round(self) -> Round:
        """Append and return the next sequential primitive round."""

        primitive_round = Round(len(self._rounds))
        self._rounds.append(primitive_round)
        return primitive_round

    def add_component(self, component: Component, *, primitive_round: Round | None = None) -> Port:
        """Validate and append a component, returning its output port."""

        if not isinstance(component, Component):
            raise TypeError("component must be a Component")
        if not self._rounds:
            raise ValueError("add a round before adding components")
        target_round = self._rounds[-1] if primitive_round is None else primitive_round
        if component.component_id is None:
            kind = re.sub(r"(?<!^)(?=[A-Z])", "_", type(component).__name__).lower()
            generated_id = f"{kind}_{target_round.number}_{len(target_round.components)}"
            component = copy(component)
            object.__setattr__(component, "component_id", generated_id)
        if component.component_id in self._ports:
            raise ValueError(f"graph source {component.component_id!r} already exists")

        if not any(target_round is existing_round for existing_round in self._rounds):
            raise ValueError("target round does not belong to this primitive")
        if target_round is not self._rounds[-1]:
            raise ValueError("components may only be appended to the current round")

        for component_input in component.inputs:
            source_id = component_input.source.owner_id
            try:
                actual_port = self._ports[source_id]
            except KeyError as error:
                raise ValueError(
                    f"input source {source_id!r} is not available in this graph"
                ) from error
            if component_input.source != actual_port:
                raise ValueError(f"input source {source_id!r} does not match its graph port type")

        target_round._append(component)
        self._components[component.component_id] = component
        self._ports[component.component_id] = component.output
        return component.output

    def join(self, *values: PortLike) -> PortLike:
        """Join homogeneous values as structural wiring.

        A single value remains a selection. Multiple sources become an
        addressable edge binding rather than a semantic graph component.
        """

        if not values:
            raise ValueError("structural wiring requires at least one value")
        if len(values) == 1:
            return as_selection(values[0])
        selections = tuple(as_selection(value) for value in values)
        domain = selections[0].value_type.domain
        if any(item.value_type.domain != domain for item in selections[1:]):
            raise ValueError("structural wiring requires one homogeneous domain")
        output_type = ValueType(domain, (sum(item.value_type.unit_count for item in selections),))
        return self._add_binding(BindingKind.JOIN, selections, output_type)

    def pack_bits(
        self,
        value: PortLike,
        word_width: int,
        *,
        output_domain=None,
    ) -> Port:
        """View consecutive MSB-first bits as fixed-width words."""

        from claasp_next.domains import BinaryExtensionField, Bit, Word

        selection = as_selection(value)
        if not isinstance(selection.value_type.domain, Bit):
            raise ValueError("pack_bits input must use the Bit domain")
        if not isinstance(word_width, int) or isinstance(word_width, bool) or word_width <= 0:
            raise ValueError("word_width must be a positive integer")
        if selection.value_type.unit_count % word_width:
            raise ValueError("input bit count must be a multiple of word_width")
        if output_domain is not None:
            if not isinstance(output_domain, BinaryExtensionField):
                raise TypeError("output_domain must be a BinaryExtensionField")
            if output_domain.degree != word_width:
                raise ValueError("binary-field degree must equal word_width")
        domain = output_domain if output_domain is not None else Word(word_width)
        output_type = ValueType(domain, (selection.value_type.unit_count // word_width,))
        return self._add_binding(
            BindingKind.PACK_BITS,
            (selection,),
            output_type,
            word_width=word_width,
        )

    def view(self, value: PortLike) -> Port:
        """Give an ordered selection its own non-semantic wiring boundary."""

        selection = as_selection(value)
        return self._add_binding(BindingKind.VIEW, (selection,), selection.value_type)

    def unpack_bits(self, value: PortLike) -> Port:
        """View fixed-width words as consecutive MSB-first bits."""

        from claasp_next.domains import BinaryExtensionField, Bit, Word

        selection = as_selection(value)
        domain = selection.value_type.domain
        if not isinstance(domain, (Word, BinaryExtensionField)):
            raise ValueError("unpack_bits input must use a Word or binary-field domain")
        word_width = domain.width if isinstance(domain, Word) else domain.degree
        output_type = ValueType(Bit(), (selection.value_type.unit_count * word_width,))
        return self._add_binding(
            BindingKind.UNPACK_BITS,
            (selection,),
            output_type,
            word_width=word_width,
        )

    def _add_binding(
        self,
        kind: BindingKind,
        inputs: tuple[Selection, ...],
        output_type: ValueType,
        *,
        word_width: int | None = None,
        binding_id: str | None = None,
        _validate_inputs: bool = True,
    ) -> Port:
        if _validate_inputs:
            for selection in inputs:
                actual = self._ports.get(selection.source.owner_id)
                if actual != selection.source:
                    raise ValueError("binding input does not match its graph port type")
        if binding_id is None:
            binding_id = f"__{kind.value}_{len(self._bindings)}"
        if binding_id in self._ports:
            raise ValueError(f"graph source {binding_id!r} already exists")
        binding = ValueBinding(binding_id, kind, inputs, output_type, word_width)
        self._bindings[binding_id] = binding
        self._ports[binding_id] = binding.output
        return binding.output

    def resolve_selection(
        self, selection: Selection, values: Mapping[str, tuple], cache=None
    ) -> tuple:
        """Resolve a selection through structural bindings for a representation."""

        cache = {} if cache is None else cache

        def available(source_id: str) -> bool:
            return source_id in values or source_id in cache

        def selected(item: Selection) -> tuple:
            source = (
                tuple(values[item.source.owner_id])
                if item.source.owner_id in values
                else cache[item.source.owner_id]
            )
            return tuple(source[position] for position in item.positions)

        pending = [selection.source.owner_id]
        while pending:
            source_id = pending[-1]
            if available(source_id):
                pending.pop()
                continue
            try:
                binding = self._bindings[source_id]
            except KeyError as error:
                raise KeyError(f"graph source {source_id!r} has no available value") from error
            missing = tuple(
                item.source.owner_id
                for item in binding.inputs
                if not available(item.source.owner_id)
            )
            if missing:
                pending.extend(reversed(missing))
                continue
            operands = tuple(selected(item) for item in binding.inputs)
            if binding.kind is BindingKind.JOIN:
                result = tuple(unit for operand in operands for unit in operand)
            elif binding.kind is BindingKind.VIEW:
                result = operands[0]
            elif binding.kind is BindingKind.PACK_BITS:
                bits = operands[0]
                groups = tuple(
                    bits[start : start + binding.word_width]
                    for start in range(0, len(bits), binding.word_width)
                )
                result = tuple(
                    sum(
                        int(bit) << (binding.word_width - 1 - index)
                        for index, bit in enumerate(group)
                    )
                    if all(isinstance(bit, int) for bit in group)
                    else tuple(group)
                    for group in groups
                )
            elif binding.kind is BindingKind.UNPACK_BITS:
                result_units = []
                for unit in operands[0]:
                    if isinstance(unit, int):
                        result_units.extend(
                            (unit >> (binding.word_width - 1 - bit)) & 1
                            for bit in range(binding.word_width)
                        )
                    else:
                        result_units.extend(unit)
                result = tuple(result_units)
            else:  # pragma: no cover - closed enum
                raise AssertionError("unknown graph binding")
            cache[source_id] = result
            pending.pop()

        source_id = selection.source.owner_id
        source = tuple(values[source_id]) if source_id in values else cache[source_id]
        return tuple(source[position] for position in selection.positions)

    def selection_bit_sources(self, selection: Selection) -> tuple[tuple[str, int], ...]:
        """Flatten a selection to the encoded bits of semantic graph sources."""

        values = {}
        ports = tuple(self._input_ports.values()) + tuple(
            component.output for component in self.components
        )
        for port in ports:
            width = port.value_type.domain.encoded_bit_size
            if width is None:
                raise TypeError("graph wiring requires canonically encoded domains")
            units = []
            for position in range(port.value_type.unit_count):
                refs = tuple((port.owner_id, position * width + bit) for bit in range(width))
                units.append(refs[0] if width == 1 else refs)
            values[port.owner_id] = tuple(units)
        selected = self.resolve_selection(selection, values)
        return tuple(
            ref
            for unit in selected
            for ref in ((unit,) if len(unit) == 2 and isinstance(unit[0], str) else unit)
        )

    def add_composite(
        self,
        definition,
        bindings: Mapping[str, PortLike],
        *,
        scope_id: str | None = None,
        primitive_round: Round | None = None,
    ):
        """Instantiate a reusable definition and lower its leaves into this graph."""

        from claasp_next.graph.composite import CompositeDefinition, CompositeInstance

        if not isinstance(definition, CompositeDefinition):
            raise TypeError("definition must be a CompositeDefinition")
        if not self._rounds:
            raise ValueError("add a round before adding a composite")
        target_round = self._rounds[-1] if primitive_round is None else primitive_round
        if target_round is not self._rounds[-1]:
            raise ValueError("composites may only be appended to the current round")
        if not isinstance(bindings, Mapping):
            raise TypeError("bindings must map composite input names to graph ports")
        expected = set(definition.inputs)
        if set(bindings) != expected:
            missing = sorted(expected - set(bindings))
            unexpected = sorted(set(bindings) - expected)
            raise ValueError(
                f"composite bindings do not match: missing={missing}, unexpected={unexpected}"
            )

        normalized: dict[str, Selection] = {}
        for name, value_type in definition.input_types:
            selection = as_selection(bindings[name])
            actual = self.port(selection.source.owner_id)
            if actual != selection.source:
                raise ValueError(f"binding {name!r} does not match its graph port type")
            if selection.value_type != value_type:
                raise ValueError(
                    f"binding {name!r} has type {selection.value_type!r}, expected {value_type!r}"
                )
            normalized[name] = selection

        if scope_id is None:
            kind = re.sub(r"(?<!^)(?=[A-Z])", "_", definition.name).lower()
            scope_id = f"{kind}_{target_round.number}_{len(target_round.scopes)}"
        if not isinstance(scope_id, str) or not scope_id or "/" in scope_id:
            raise ValueError("scope_id must be a non-empty local path segment")
        if scope_id in self._scopes or scope_id in self._ports:
            raise ValueError(f"graph scope {scope_id!r} already exists")

        remapped: dict[str, Selection] = dict(normalized)
        for binding in definition.bindings:
            remapped[binding.binding_id] = Port(
                f"{scope_id}/{binding.binding_id}", binding.output_type
            ).select_all()
        for components in definition.rounds:
            for template_component in components:
                if template_component.component_id is None:
                    raise ValueError(
                        "composite definitions must contain assigned component identifiers"
                    )
                remapped[template_component.component_id] = Port(
                    f"{scope_id}/{template_component.component_id}", template_component.output_type
                ).select_all()

        def remap(selection: Selection) -> Selection:
            source = remapped[selection.source.owner_id]
            return source[selection.positions]

        for binding in definition.bindings:
            self._add_binding(
                binding.kind,
                tuple(remap(item) for item in binding.inputs),
                binding.output_type,
                word_width=binding.word_width,
                binding_id=f"{scope_id}/{binding.binding_id}",
                _validate_inputs=False,
            )

        component_ids: list[str] = []
        for components in definition.rounds:
            for template_component in components:
                component = copy(template_component)
                local_id = template_component.component_id
                component_id = f"{scope_id}/{local_id}"
                object.__setattr__(component, "component_id", component_id)
                object.__setattr__(
                    component, "inputs", tuple(remap(item) for item in component.inputs)
                )
                output = self.add_component(component, primitive_round=target_round)
                remapped[local_id] = output.select_all()
                component_ids.append(component_id)

        outputs = tuple((name, remap(selection)) for name, selection in definition.outputs)
        instance = CompositeInstance(
            scope_id,
            definition,
            tuple(normalized.items()),
            outputs,
            tuple(component_ids),
            self,
        )
        self._scopes[scope_id] = instance
        target_round._append_scope(instance)

        for template in definition.nested_scopes:
            nested_path = f"{scope_id}/{template.path}"
            nested = CompositeInstance(
                nested_path,
                template.definition,
                tuple((name, remap(selection)) for name, selection in template.input_bindings),
                tuple((name, remap(selection)) for name, selection in template.output_bindings),
                tuple(f"{scope_id}/{component_id}" for component_id in template.component_ids),
                self,
            )
            self._scopes[nested_path] = nested
            target_round._append_scope(nested)
        return instance

    def set_output(self, output: PortLike | Sequence[PortLike]) -> None:
        """Declare the ordered logical units returned by this primitive."""

        if isinstance(output, Sequence) and not isinstance(output, (Port, Selection)):
            output = self.join(*output)
        output = as_selection(output)
        try:
            actual_port = self._ports[output.source.owner_id]
        except KeyError as error:
            raise ValueError("output source is not available in this graph") from error
        if output.source != actual_port:
            raise ValueError("output source does not match its graph port type")
        self._output = output

    def evaluate(self, *args: object, **kwargs: object) -> int | tuple[int, ...] | None:
        """Evaluate with convenient boundary encoding and return the primitive output.

        Inputs may be supplied as one mapping, as keyword arguments, or in the
        primitive's declared input order. Bit, byte/extension-field, and word
        vectors accept packed integers and produce a packed integer output.
        """

        result = self.evaluate_with_trace(*args, **kwargs)
        if result.output is None or self.output is None:
            return None
        return self._encode_boundary(result.output, self.output.value_type)

    def evaluate_with_trace(self, *args: object, **kwargs: object):
        """Evaluate like :meth:`evaluate` and retain all intermediate values."""

        from claasp_next.representations.execution import ScalarExecutionDriver

        supplied = self._bind_inputs(args, kwargs)
        decoded = {
            name: self._decode_boundary(value, self._input_ports[name].value_type)
            for name, value in supplied.items()
        }
        return ScalarExecutionDriver().evaluate(self, decoded)

    def analyze(self):
        """Return the high-level analysis facade for this primitive."""

        from claasp_next.analysis import Analysis

        return Analysis(self)

    def inverse(self, recover_input: str | int = 0, **options):
        """Return a validated inverse graph for one primitive input.

        See :func:`claasp_next.transformations.invert_primitive` for retained-input options and
        the typed transformation result.
        """

        from claasp_next.transformations import invert_primitive

        return invert_primitive(self, recover_input, **options)

    def partial_inverse(self, target: PortLike, *, known, **options):
        """Return a solver-free partial inverse from explicit known wires."""

        from claasp_next.transformations import partial_inverse

        return partial_inverse(self, target, known=known, **options)

    def sliced(self, outputs=None, **options):
        """Return a validated dependency slice of this graph."""

        from claasp_next.transformations import slice_primitive

        return slice_primitive(self, outputs, **options)

    def reduced_rounds(self, number_of_rounds: int):
        """Return the validated prefix ending at a published round state."""

        from claasp_next.transformations import reduce_rounds

        return reduce_rounds(self, number_of_rounds)

    def without_key_schedule(self, *, keep_round_key_injection: bool = True):
        """Return a graph without its computed key schedule."""

        from claasp_next.transformations import remove_key_schedule

        return remove_key_schedule(
            self,
            keep_round_key_injection=keep_round_key_injection,
        )

    def with_inlined_reorderings(self):
        """Return a graph whose exact reorder operations are bindings."""

        from claasp_next.transformations import inline_reorderings

        return inline_reorderings(self)

    def pruned(self):
        """Return this graph's validated output dependency closure."""

        from claasp_next.transformations import prune_orphans

        return prune_orphans(self)

    def paired_xor(self, *, shared_inputs=(), **options):
        """Return two scoped realizations and their XOR observations."""

        from claasp_next.transformations import paired_xor_primitive

        return paired_xor_primitive(self, shared_inputs=shared_inputs, **options)

    def diagram(self, annotation=None):
        """Compile this graph and an optional trace or trail to diagram IR."""

        from claasp_next.annotations import GraphAnnotation
        from claasp_next.representations.diagrams import DiagramCompiler

        if (
            annotation is not None
            and not isinstance(annotation, GraphAnnotation)
            and hasattr(annotation, "annotate")
        ):
            annotation = annotation.annotate(self)
        return DiagramCompiler().compile(self, annotation)

    def draw(self, format: str = "ascii", annotation=None):  # noqa: A002 - public format API
        """Render this primitive as routed ASCII art, TikZ, or PDF.

        PDF rendering requires the optional ``pdflatex`` command. ASCII and
        TikZ generation have no third-party dependencies.
        """

        from claasp_next.representations.diagrams import ASCIIArtSerializer, TikZSerializer

        diagram = self.diagram(annotation)
        if format == "ascii":
            return ASCIIArtSerializer().serialize(diagram)
        tikz = TikZSerializer().serialize(diagram)
        if format == "tikz":
            return tikz
        if format == "pdf":
            from claasp_next.drivers.renderers import LaTeXDriver

            return LaTeXDriver().render(tikz).pdf
        raise ValueError("diagram format must be 'ascii', 'tikz', or 'pdf'")

    def _bind_inputs(
        self, args: tuple[object, ...], kwargs: Mapping[str, object]
    ) -> Mapping[str, object]:
        if kwargs and args:
            raise TypeError(
                "use positional arguments, keyword arguments, or one mapping; do not mix them"
            )
        if kwargs:
            supplied = dict(kwargs)
        elif len(args) == 1 and isinstance(args[0], Mapping):
            supplied = dict(args[0])
        else:
            if len(args) != len(self._input_ports):
                raise TypeError(
                    f"expected {len(self._input_ports)} positional inputs, got {len(args)}"
                )
            supplied = dict(zip(self._input_ports, args))
        expected = set(self._input_ports)
        if set(supplied) != expected:
            missing = sorted(expected - set(supplied))
            unexpected = sorted(set(supplied) - expected)
            raise ValueError(
                f"primitive inputs do not match: missing={missing}, unexpected={unexpected}"
            )
        return supplied

    @staticmethod
    def _decode_boundary(value: object, value_type: ValueType) -> tuple[int, ...]:
        from claasp_next.domains import Bit, PrimeField
        from claasp_next.encoding import bits_from_int, units_from_int

        if isinstance(value, int) and not isinstance(value, bool):
            if isinstance(value_type.domain, Bit):
                return bits_from_int(value, value_type.unit_count)
            if isinstance(value_type.domain, PrimeField):
                if value_type.unit_count != 1:
                    raise TypeError("prime-field vectors require a tuple of field elements")
                return (value,)
            width = value_type.domain.encoded_bit_size
            if width is not None:
                return units_from_int(value, width, value_type.unit_count)
        if isinstance(value, Sequence) and not isinstance(value, str):
            return tuple(value)
        raise TypeError("primitive inputs must be packed integers or sequences of logical units")

    @staticmethod
    def _encode_boundary(value: tuple[int, ...], value_type: ValueType) -> int | tuple[int, ...]:
        from claasp_next.domains import Bit, PrimeField
        from claasp_next.encoding import int_from_bits, int_from_units

        if isinstance(value_type.domain, PrimeField):
            return value[0] if value_type.unit_count == 1 else value
        if isinstance(value_type.domain, Bit):
            return int_from_bits(value)
        width = value_type.domain.encoded_bit_size
        return value if width is None else int_from_units(value, width)
