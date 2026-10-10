"""Validated typed primitive graph."""

import re
from collections.abc import Iterable, Mapping, Sequence
from copy import copy
from dataclasses import dataclass
from inspect import Parameter, formatannotation, signature
from types import MappingProxyType
from typing import TYPE_CHECKING

from claasp.graph.array_type import ArrayType
from claasp.graph.binding import BindingKind, ValueBinding
from claasp.graph.component import Component
from claasp.graph.metadata import (
    InputVisibility,
    PrimitiveInput,
    PrimitiveKind,
    infer_primitive_kind,
)
from claasp.graph.port import Port, PortLike, Selection, as_selection
from claasp.graph.realization import (
    RealizationDescriptor,
    RealizationMaturity,
    RealizationSelectionPolicy,
    UnsupportedRealizationError,
    normalize_realization_contract,
    select_realization,
)
from claasp.graph.round import Round

if TYPE_CHECKING:
    from claasp.analysis import Analysis
    from claasp.catalogue import ParameterSetRecord


def _normalize_primitive_inputs(
    inputs: Mapping[str, ArrayType | PrimitiveInput],
) -> tuple[dict[str, PrimitiveInput], dict[str, Port]]:
    """Validate input declarations and create their descriptors and ports."""

    descriptors: dict[str, PrimitiveInput] = {}
    ports: dict[str, Port] = {}
    for name, supplied in inputs.items():
        if not isinstance(name, str):
            raise TypeError("input names must be strings")
        if not name:
            raise ValueError("input names must not be empty")
        if isinstance(supplied, PrimitiveInput):
            descriptor = supplied
        elif isinstance(supplied, ArrayType):
            visibility = (
                InputVisibility.SECRET
                if name in {"key", "secret", "secret_key"}
                else InputVisibility.PUBLIC
            )
            descriptor = PrimitiveInput(supplied, role=name, visibility=visibility)
        else:
            raise TypeError(f"input {name!r} must have an ArrayType or PrimitiveInput")
        descriptors[name] = descriptor
        ports[name] = Port(name, descriptor.array_type)
    return descriptors, ports


class _OfficialInstances(tuple):
    """Immutable official constructor configurations with a readable display."""

    primitive_name: str

    def __new__(
        cls,
        primitive_name: str,
        values: Iterable["ParameterSetRecord"],
    ) -> "_OfficialInstances":
        instance = super().__new__(cls, values)
        instance.primitive_name = primitive_name
        return instance

    def __repr__(self) -> str:
        lines = [f"Official instances for {self.primitive_name} ({len(self)})"]
        if not self:
            lines.append("  None declared in the primitive catalogue")
            return "\n".join(lines)
        for index, record in enumerate(self):
            arguments = ", ".join(f"{name}={value!r}" for name, value in record.values.items())
            lines.append(f"  [{index}] {self.primitive_name}({arguments})")
        return "\n".join(lines)


class _ConstructorParameters(Mapping[str, Parameter]):
    """Read-only public constructor signature with concise shell output."""

    def __init__(self, primitive_class: type) -> None:
        self.primitive_name = primitive_class.__name__
        self._values = {
            name: item
            for name, item in signature(primitive_class).parameters.items()
            if not name.startswith("_")
        }

    def __getitem__(self, name: str) -> Parameter:
        return self._values[name]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    @staticmethod
    def _format_default(value: object) -> str:
        if value is Parameter.empty:
            return "required"
        if isinstance(value, (tuple, list)) and len(value) > 8:
            return f"<{type(value).__name__} with {len(value)} items>"
        rendered = repr(value)
        return rendered if len(rendered) <= 80 else f"<{type(value).__name__}>"

    def __repr__(self) -> str:
        lines = [f"Customizable parameters for {self.primitive_name} ({len(self)})"]
        for item in self._values.values():
            if item.annotation is Parameter.empty:
                annotation = ""
            else:
                annotation_name = formatannotation(item.annotation).replace("collections.abc.", "")
                annotation = f": {annotation_name}"
            lines.append(f"  {item.name}{annotation} = {self._format_default(item.default)}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class PrimitiveInputDetails:
    """Beginner-facing description of one primitive input.

    EXAMPLES::

        >>> from claasp import InputVisibility, PrimitiveInputDetails
        >>> item = PrimitiveInputDetails("key", 128, "key", InputVisibility.SECRET)
        >>> (item.name, item.bit_size, item.visibility.value)
        ('key', 128, 'secret')
    """

    name: str
    bit_size: int | None
    role: str
    visibility: InputVisibility


@dataclass(frozen=True, slots=True)
class PrimitiveDetails:
    """Structured primitive summary with a readable interactive representation.

    EXAMPLES::

        >>> from claasp.primitives import AES
        >>> details = AES().details()
        >>> (details.instance, details.number_of_rounds, details.realization)
        ('AES-128', 10, 'lookup')
    """

    kind: PrimitiveKind
    instance: str
    inputs: tuple[PrimitiveInputDetails, ...]
    output_bit_size: int | None
    number_of_rounds: int
    realization: str

    def __str__(self) -> str:
        lines = [
            "Primitive details",
            f"  Type: {self.kind.value.replace('_', ' ')}",
            f"  Instance: {self.instance}",
            "  Inputs:",
        ]
        for item in self.inputs:
            size = "no fixed encoding" if item.bit_size is None else f"{item.bit_size} bits"
            lines.append(f"    {item.name}: {size} ({item.visibility.value})")
        output_size = (
            "no fixed encoding" if self.output_bit_size is None else f"{self.output_bit_size} bits"
        )
        lines.extend(
            (
                f"  Output: {output_size}",
                f"  Rounds: {self.number_of_rounds}",
                f"  Realization: {self.realization}",
            )
        )
        return "\n".join(lines)

    def __repr__(self) -> str:
        return str(self)


class PublishedValues(tuple):
    """An immutable published graph sequence with a concise representation.

    EXAMPLES::

        >>> from claasp.primitives import AES
        >>> AES(number_of_rounds=1).graph.round_keys
        Round keys (2)
          [0] input key: 128 bits
          [1] derived graph value: 128 bits
    """

    label: str
    _primitive: "Primitive"

    def __new__(cls, label: str, values: Iterable[object], primitive: "Primitive"):
        instance = super().__new__(cls, values)
        instance.label = label
        instance._primitive = primitive
        return instance

    @staticmethod
    def _bit_size(value: object) -> int | None:
        array_type = getattr(value, "array_type", None)
        return None if array_type is None else array_type.encoded_bit_size

    def __repr__(self) -> str:
        lines = [f"{self.label} ({len(self)})"]
        for index, value in enumerate(self):
            bit_size = self._bit_size(value)
            suffix = "" if bit_size is None else f": {bit_size} bits"
            if isinstance(value, (Port, Selection)):
                source = value.owner_id if isinstance(value, Port) else value.source.owner_id
                description = (
                    f"input {source}"
                    if source in self._primitive._input_ports
                    else "derived graph value"
                )
            elif isinstance(value, Mapping):
                description = ", ".join(value) or "empty observation"
            else:
                description = type(value).__name__.replace("_", " ").lower()
            lines.append(f"  [{index}] {description}{suffix}")
        return "\n".join(lines)


class PrimitiveGraph:
    """Read-only structural view of a completed primitive graph.

    EXAMPLES::

        >>> from claasp.primitives import AES
        >>> graph = AES(number_of_rounds=2).graph
        >>> (len(graph.rounds), len(graph.input_ports))
        (3, 2)
    """

    def __init__(self, primitive: "Primitive") -> None:
        self._primitive = primitive

    @property
    def input_descriptors(self) -> Mapping[str, PrimitiveInput]:
        """Return typed input roles and default visibility by name."""

        return dict(self._primitive._input_descriptors)

    @property
    def secret_inputs(self) -> tuple[str, ...]:
        """Return secret input names in declaration order."""

        return tuple(
            name for name, item in self._primitive._input_descriptors.items() if item.is_secret
        )

    @property
    def input_ports(self) -> Mapping[str, Port]:
        """Return the graph's name-to-input-port mapping."""

        return dict(self._primitive._input_ports)

    def input(self, selector: str | int) -> Port:
        """Return one input port by name or zero-based declaration position.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().graph.input("key").owner_id
            'key'
        """

        return self._primitive._input(selector)

    def input_descriptor(self, name: str) -> PrimitiveInput:
        """Return the type, role, and visibility declared for one input.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().graph.input_descriptor("key").visibility.value
            'secret'
        """

        return self._primitive._input_descriptor(name)

    def inputs(self, *selectors: str | int) -> Sequence[Port]:
        """Return input ports in declaration or explicitly requested order.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> tuple(port.owner_id for port in AES().graph.inputs())
            ('plaintext', 'key')
        """

        return self._primitive._inputs(*selectors)

    @property
    def rounds(self) -> tuple[Round, ...]:
        """Return authored rounds in deterministic order."""

        return tuple(self._primitive._rounds)

    @property
    def components(self) -> tuple[Component, ...]:
        """Return semantic components in deterministic graph order."""

        return tuple(self._primitive._components.values())

    @property
    def bindings(self) -> tuple[ValueBinding, ...]:
        """Return structural wiring values in construction order."""

        return tuple(self._primitive._bindings.values())

    @property
    def scopes(self) -> tuple[object, ...]:
        """Return composite instances in deterministic path order."""

        return tuple(self._primitive._scopes.values())

    @property
    def output(self) -> Selection | None:
        """Return the selected graph output."""

        return self._primitive._output

    @property
    def round_keys(self) -> PublishedValues:
        """Return published round-key selections with a concise summary."""

        return PublishedValues(
            "Round keys", getattr(self._primitive, "_published_round_keys", ()), self._primitive
        )

    @property
    def round_outputs(self) -> PublishedValues:
        """Return the explicitly published output of each cryptographic round."""

        values = tuple(
            outputs["round_output"]
            for outputs in self.intermediate_outputs
            if "round_output" in outputs
        )
        return PublishedValues("Round outputs", values, self._primitive)

    @property
    def key_schedule_states(self) -> PublishedValues:
        """Return published key-schedule states with a concise summary."""

        return PublishedValues(
            "Key-schedule states",
            getattr(self._primitive, "_published_key_schedule_states", ()),
            self._primitive,
        )

    @property
    def intermediate_outputs(self) -> tuple[Mapping[str, object], ...]:
        """Return named inspectable outputs for each round that publishes them."""

        published = getattr(self._primitive, "_published_intermediate_outputs", {})
        return tuple(
            MappingProxyType(dict(published[primitive_round.number]))
            for primitive_round in self._primitive._rounds
            if primitive_round.number in published
        )

    @property
    def _intermediate_components(self) -> tuple[Mapping[str, Component], ...]:
        """Resolve published intermediate outputs to their producing components."""

        result = []
        for outputs in self.intermediate_outputs:
            components = {}
            for name, value in outputs.items():
                if name == "round_output" or not isinstance(value, (Port, Selection)):
                    continue
                owner_id = value.owner_id if isinstance(value, Port) else value.source.owner_id
                component = self._primitive._components.get(owner_id)
                if component is not None:
                    components[name] = component
            result.append(MappingProxyType(components))
        return tuple(result)

    def port(self, owner_id: str) -> Port:
        """Resolve an input, component, or binding output port by identity.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().graph.port("plaintext").owner_id
            'plaintext'
        """

        return self._primitive._port(owner_id)

    def component(self, component_id: str) -> Component:
        """Resolve a semantic component by its deterministic identifier.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> graph = AES(number_of_rounds=1).graph
            >>> graph.component(graph.components[0].component_id) is graph.components[0]
            True
        """

        return self._primitive._component(component_id)

    def scope(self, path: str):
        """Return a composite instance by its deterministic hierarchical path.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> callable(AES().graph.scope)
            True
        """

        return self._primitive._scope(path)

    def resolve_selection(
        self, selection: Selection, values: Mapping[str, tuple], cache=None
    ) -> tuple:
        """Resolve a selection through structural bindings.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> graph = AES().graph
            >>> graph.resolve_selection(graph.input("plaintext").select_all(), {"plaintext": tuple(range(16))})[:3]
            (0, 1, 2)
        """

        return self._primitive._resolve_selection(selection, values, cache)

    def selection_bit_sources(self, selection: Selection) -> tuple[tuple[str, int], ...]:
        """Flatten a selection to encoded semantic-source bits.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().graph.selection_bit_sources(AES().graph.input("plaintext")[:1])[:3]
            (('plaintext', 0), ('plaintext', 1), ('plaintext', 2))
        """

        return self._primitive._selection_bit_sources(selection)


class PrimitiveEditor:
    """Copy-producing transformations grouped away from routine primitive use.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> editor = Speck(number_of_rounds=2).edit
        >>> (callable(editor.reduce_rounds), callable(editor.inverse))
        (True, True)
    """

    def __init__(self, primitive: "Primitive") -> None:
        self._primitive = primitive

    def inverse(self, recover_input: str | int = 0, **options):
        """Return a validated inverse graph for one primitive input.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> Speck(number_of_rounds=1).edit.inverse().primitive.family_name
            'speck_inverse'
        """

        from claasp.transformations import invert_primitive

        return invert_primitive(self._primitive, recover_input, **options)

    def partial_inverse(self, target: PortLike, *, known, **options):
        """Return a solver-free partial inverse from explicit known wires.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> callable(Speck(number_of_rounds=1).edit.partial_inverse)
            True
        """

        from claasp.transformations import partial_inverse

        return partial_inverse(self._primitive, target, known=known, **options)

    def slice(self, outputs=None, **options):
        """Return a validated dependency slice of the graph.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> source = Speck(number_of_rounds=2)
            >>> source.edit.slice(source.graph.round_outputs[0]).primitive.details().number_of_rounds
            1
        """

        from claasp.transformations import slice_primitive

        return slice_primitive(self._primitive, outputs, **options)

    def reduce_rounds(self, number_of_rounds: int):
        """Return the validated prefix ending at a published round state.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> Speck(number_of_rounds=2).edit.reduce_rounds(1).primitive.details().number_of_rounds
            1
        """

        from claasp.transformations import reduce_rounds

        return reduce_rounds(self._primitive, number_of_rounds)

    def remove_key_schedule(self, *, keep_round_key_injection: bool = True):
        """Return a graph without its computed key schedule.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> result = Speck(number_of_rounds=1).edit.remove_key_schedule().primitive
            >>> tuple(result.graph.input_ports)
            ('plaintext', 'round_key_0')
        """

        from claasp.transformations import remove_key_schedule

        return remove_key_schedule(
            self._primitive,
            keep_round_key_injection=keep_round_key_injection,
        )

    def inline_reorderings(self):
        """Return a graph whose exact reorder operations are bindings.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> result = Speck(number_of_rounds=1).edit.inline_reorderings()
            >>> result.primitive.transformation_provenance[-1].operation
            'inline_reorderings'
        """

        from claasp.transformations import inline_reorderings

        return inline_reorderings(self._primitive)

    def prune(self):
        """Return the graph's validated output dependency closure.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> result = Speck(number_of_rounds=1).edit.prune()
            >>> result.primitive.transformation_provenance[-1].operation
            'prune_orphans'
        """

        from claasp.transformations import prune_orphans

        return prune_orphans(self._primitive)

    def pair_xor(self, *, shared_inputs=(), **options):
        """Return two scoped realizations and their XOR observations.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> paired = Speck(number_of_rounds=1).edit.pair_xor(shared_inputs=("key",))
            >>> tuple(paired.primitive.graph.input_ports)
            ('left_plaintext', 'right_plaintext', 'key')
        """

        from claasp.transformations import paired_xor_primitive

        return paired_xor_primitive(self._primitive, shared_inputs=shared_inputs, **options)

    def with_input_visibility(self, **overrides: InputVisibility | str) -> "Primitive":
        """Return the same graph with study-specific input visibility metadata.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().edit.with_input_visibility(key="public").graph.secret_inputs
            ()
        """

        primitive = self._primitive
        unexpected = set(overrides) - set(primitive._input_descriptors)
        if unexpected:
            raise KeyError(f"primitive inputs do not exist: {sorted(unexpected)}")
        derived = copy(primitive)
        derived._input_descriptors = {
            name: descriptor.with_visibility(overrides.get(name, descriptor.visibility))
            for name, descriptor in primitive._input_descriptors.items()
        }
        derived._graph = PrimitiveGraph(derived)
        return derived


class Primitive:
    """A validated, executable round-oriented directed acyclic graph.

    A primitive owns typed input ports, immutable component descriptions, and
    an explicit output binding. Use :class:`PrimitiveBuilder` to author a new
    graph; completed primitives expose evaluation, analysis, transformations,
    and read-only graph inspection.

    EXAMPLES::

        >>> from claasp import PrimitiveBuilder, ArrayType
        >>> from claasp.domains import Word
        >>> from claasp.components import Xor
        >>> nibble = ArrayType(Word(4), (1,))
        >>> builder = PrimitiveBuilder("xor_nibbles", {"left": nibble, "right": nibble})
        >>> builder.add_round()
        Round(number=0)
        >>> output = builder.add_component(Xor(builder.inputs()))
        >>> builder.set_output(output)
        >>> primitive = builder.build()
        >>> primitive.evaluate(0b1010, 0b0011)
        9
        >>> (primitive.family_name, len(primitive.graph.rounds), len(primitive.graph.components))
        ('xor_nibbles', 1, 1)
    """

    _realizations: tuple[RealizationDescriptor, ...] = ()
    _realization_builders: Mapping[str, object] = MappingProxyType({})

    @staticmethod
    def _select_configuration(configurations, **parameters):
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
    def _validate_number_of_rounds(value, *, default: int, maximum: int, name: str) -> int:
        """Resolve and validate a positive, optionally reduced round count."""

        rounds = default if value is None else value
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if not 1 <= rounds <= maximum:
            raise ValueError(f"{name} requires between 1 and {maximum} rounds")
        return rounds

    @staticmethod
    def _validate_positive_integer(value, *, name: str) -> int:
        """Validate a positive integer authoring parameter."""

        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    def __init__(
        self,
        family_name: str,
        inputs: Mapping[str, ArrayType | PrimitiveInput],
        *,
        kind: PrimitiveKind | str | None = None,
        provenance: tuple[tuple[str, str], ...] = (),
        instance_name: str | None = None,
        round_count: int | None = None,
        _builder: "PrimitiveBuilder | None" = None,
    ) -> None:
        if not isinstance(family_name, str):
            raise TypeError("family_name must be a string")
        if not family_name:
            raise ValueError("family_name must not be empty")
        if not isinstance(inputs, Mapping):
            raise TypeError("inputs must be a mapping from names to ArrayType objects")
        descriptors, ports = _normalize_primitive_inputs(inputs)

        if kind is None:
            kind = infer_primitive_kind(descriptors)
        elif not isinstance(kind, PrimitiveKind):
            kind = PrimitiveKind(kind)
        if instance_name is not None and (not isinstance(instance_name, str) or not instance_name):
            raise ValueError("instance_name must be a non-empty string or None")
        if round_count is not None and (
            not isinstance(round_count, int) or isinstance(round_count, bool) or round_count < 0
        ):
            raise ValueError("round_count must be a non-negative integer or None")

        self._family_name = family_name
        self._kind = kind
        self._instance_name = instance_name
        self._round_count = round_count
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
        self._graph = PrimitiveGraph(self)
        self._builder = _builder or PrimitiveBuilder._for_primitive(self)
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

            >>> from claasp.primitives import Speck
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

        return tuple(cls._realizations) or (cls._default_realization(),)

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
        builder = cls._realization_builders.get(name)
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
    def instances(self) -> tuple["ParameterSetRecord", ...]:
        """Return specification-approved configurations for this primitive.

        This catalogue-backed list excludes valid study configurations such as
        reduced-round variants.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES(number_of_rounds=5).instances
            Official instances for AES (3)
              [0] AES(key_bit_size=128, number_of_rounds=10)
              [1] AES(key_bit_size=192, number_of_rounds=12)
              [2] AES(key_bit_size=256, number_of_rounds=14)
        """

        from claasp.catalogue import catalogue

        primitive_name = type(self).__name__
        records: tuple[ParameterSetRecord, ...] = ()
        for primitive_class in type(self).__mro__:
            try:
                catalogue_record = catalogue.primitive(primitive_class.__name__)
            except KeyError:
                continue
            primitive_name = catalogue_record.name
            if catalogue_record.authenticity == "canonical":
                records = catalogue_record.parameter_sets
            break
        return _OfficialInstances(primitive_name, records)

    @property
    def parameters(self) -> Mapping[str, Parameter]:
        """Return the parameters accepted by this primitive's constructor.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().parameters
            Customizable parameters for AES (3)
              key_bit_size: int = 128
              number_of_rounds: int | None = None
              realization: str = 'lookup'
            >>> AES().parameters["number_of_rounds"].default is None
            True
        """

        return _ConstructorParameters(type(self))

    @property
    def graph(self) -> PrimitiveGraph:
        """Return the read-only structural view of this primitive."""

        return self._graph

    @property
    def edit(self) -> PrimitiveEditor:
        """Return copy-producing graph transformations grouped for discovery."""

        return PrimitiveEditor(self)

    @property
    def _input_descriptors_view(self) -> Mapping[str, PrimitiveInput]:
        """Typed roles and default visibility for primitive inputs."""

        return dict(self._input_descriptors)

    @property
    def _secret_inputs(self) -> tuple[str, ...]:
        """Return secret input names in declaration order."""

        return tuple(name for name, item in self._input_descriptors.items() if item.is_secret)

    def _input_descriptor(self, name: str) -> PrimitiveInput:
        """Return the typed role and visibility descriptor for one input."""

        try:
            return self._input_descriptors[name]
        except KeyError as error:
            raise KeyError(f"primitive input {name!r} does not exist") from error

    def details(self) -> PrimitiveDetails:
        """Return a concise, tab-discoverable description of this instance.

        The result has named fields for programmatic use and renders as a
        compact summary in Python shells and notebooks.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> AES().details()
            Primitive details
              Type: block cipher
              Instance: AES-128
              Inputs:
                plaintext: 128 bits (public)
                key: 128 bits (secret)
              Output: 128 bits
              Rounds: 10
              Realization: lookup
        """

        inputs = tuple(
            PrimitiveInputDetails(
                name,
                descriptor.array_type.encoded_bit_size,
                descriptor.role,
                descriptor.visibility,
            )
            for name, descriptor in self._input_descriptors.items()
        )
        output = self._output
        if output is None:
            raise ValueError("primitive details require an authored output")
        return PrimitiveDetails(
            self.kind,
            self._instance_name or type(self).__name__,
            inputs,
            output.array_type.encoded_bit_size,
            self._round_count if self._round_count is not None else len(self._rounds),
            self.realization.name,
        )

    @property
    def _input_ports_view(self) -> Mapping[str, Port]:
        """Name-to-port mapping for representations and other graph consumers."""

        return dict(self._input_ports)

    def _inputs(self, *selectors: str | int) -> Sequence[Port]:
        """Return input ports in declaration or explicitly requested order.

        With no selectors, all inputs are returned in declaration order. Names
        are preferable in specification-oriented code; zero-based positions
        are useful to generic primitive builders.
        """

        if not selectors:
            return tuple(self._input_ports.values())
        return tuple(self._input(selector) for selector in selectors)

    @property
    def _rounds_view(self) -> tuple[Round, ...]:
        """Return authored rounds as an immutable ordered tuple."""

        return tuple(self._rounds)

    def _publish_round_keys(self, round_keys: Iterable[object]) -> Sequence[object]:
        """Publish round keys without exposing their storage representation."""

        self._published_round_keys = tuple(round_keys)
        return self._published_round_keys

    def _publish_round_key(self, round_key: object) -> object:
        """Publish one round key in authoring order."""

        self._published_round_keys = (
            *getattr(self, "_published_round_keys", ()),
            round_key,
        )
        return round_key

    def _normalize_published_output(
        self, output: PortLike | Sequence[PortLike]
    ) -> PortLike | tuple[PortLike, ...]:
        """Validate an inspectable output without changing the primitive output."""

        values = (
            tuple(output)
            if isinstance(output, Sequence) and not isinstance(output, (Port, Selection))
            else (output,)
        )
        for value in values:
            selection = as_selection(value)
            try:
                actual_port = self._ports[selection.source.owner_id]
            except KeyError as error:
                raise ValueError(
                    "published output source is not available in this graph"
                ) from error
            if selection.source != actual_port:
                raise ValueError("published output source does not match its graph port type")
        return values[0] if len(values) == 1 else values

    def _set_intermediate_output(
        self,
        output: PortLike | Sequence[PortLike],
        *,
        name: str,
    ) -> object:
        """Publish one named output in the current graph round."""

        if not isinstance(name, str) or not name:
            raise ValueError("intermediate output name must be a non-empty string")
        if not self._rounds:
            raise RuntimeError("an intermediate output requires a current round")
        round_number = self._rounds[-1].number
        published = getattr(self, "_published_intermediate_outputs", None)
        if published is None:
            published = {}
            self._published_intermediate_outputs = published
        outputs = published.setdefault(round_number, {})
        if name in outputs:
            raise ValueError(
                f"intermediate output {name!r} is already set for round {round_number}"
            )
        normalized = self._normalize_published_output(output)
        outputs[name] = normalized
        return normalized

    def _publish_key_schedule_states(self, states: Iterable[object]) -> Sequence[object]:
        """Publish key-schedule states without exposing their storage representation."""

        self._published_key_schedule_states = tuple(states)
        return self._published_key_schedule_states

    def _publish_key_schedule_state(self, *values: object) -> object:
        """Publish one key-schedule state in authoring order."""

        if not values:
            raise ValueError("key-schedule state must contain at least one value")
        state = values[0] if len(values) == 1 else tuple(values)
        self._published_key_schedule_states = (
            *getattr(self, "_published_key_schedule_states", ()),
            state,
        )
        return state

    @property
    def _components_view(self) -> tuple[Component, ...]:
        """Return semantic components in deterministic graph order."""

        return tuple(self._components.values())

    @property
    def _bindings_view(self) -> tuple[ValueBinding, ...]:
        """Return structural wiring values in construction order."""

        return tuple(self._bindings.values())

    @property
    def _scopes_view(self) -> tuple[object, ...]:
        """Composite instances in deterministic path order."""

        return tuple(self._scopes.values())

    @property
    def _output_view(self) -> Selection | None:
        """Return the selected graph output, or ``None`` before binding it."""

        return self._output

    def _input(self, selector: str | int) -> Port:
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

    def _port(self, owner_id: str) -> Port:
        """Resolve an input, component, or binding output port by identity."""

        try:
            return self._ports[owner_id]
        except KeyError as error:
            raise KeyError(f"graph source {owner_id!r} does not exist") from error

    def _component(self, component_id: str) -> Component:
        """Resolve a semantic component by its deterministic identifier."""

        try:
            return self._components[component_id]
        except KeyError as error:
            raise KeyError(f"component {component_id!r} does not exist") from error

    def _scope(self, path: str):
        """Return a composite instance by its deterministic hierarchical path."""

        try:
            return self._scopes[path]
        except KeyError as error:
            raise KeyError(f"composite scope {path!r} does not exist") from error

    def _add_round(self) -> Round:
        """Append and return the next sequential primitive round."""

        primitive_round = Round(len(self._rounds))
        self._rounds.append(primitive_round)
        return primitive_round

    def _add_component(self, component: Component, *, primitive_round: Round | None = None) -> Port:
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

    def _join(self, *values: PortLike) -> PortLike:
        """Join homogeneous values as structural wiring.

        A single value remains a selection. Multiple sources become an
        addressable edge binding rather than a semantic graph component.
        """

        if not values:
            raise ValueError("structural wiring requires at least one value")
        if len(values) == 1:
            return as_selection(values[0])
        selections = tuple(as_selection(value) for value in values)
        domain = selections[0].array_type.domain
        if any(item.array_type.domain != domain for item in selections[1:]):
            raise ValueError("structural wiring requires one homogeneous domain")
        output_type = ArrayType(domain, (sum(item.array_type.unit_count for item in selections),))
        return self._add_binding(BindingKind.JOIN, selections, output_type)

    def _pack_bits(
        self,
        value: PortLike,
        word_width: int,
        *,
        output_domain=None,
    ) -> Port:
        """View consecutive MSB-first bits as fixed-width words."""

        from claasp.domains import BinaryExtensionField, Bit, Word

        selection = as_selection(value)
        if not isinstance(selection.array_type.domain, Bit):
            raise ValueError("pack_bits input must use the Bit domain")
        if not isinstance(word_width, int) or isinstance(word_width, bool) or word_width <= 0:
            raise ValueError("word_width must be a positive integer")
        if selection.array_type.unit_count % word_width:
            raise ValueError("input bit count must be a multiple of word_width")
        if output_domain is not None:
            if not isinstance(output_domain, BinaryExtensionField):
                raise TypeError("output_domain must be a BinaryExtensionField")
            if output_domain.degree != word_width:
                raise ValueError("binary-field degree must equal word_width")
        domain = output_domain if output_domain is not None else Word(word_width)
        output_type = ArrayType(domain, (selection.array_type.unit_count // word_width,))
        return self._add_binding(
            BindingKind.PACK_BITS,
            (selection,),
            output_type,
            word_width=word_width,
        )

    def _view(self, value: PortLike) -> Port:
        """Give an ordered selection its own non-semantic wiring boundary."""

        selection = as_selection(value)
        return self._add_binding(BindingKind.VIEW, (selection,), selection.array_type)

    def _unpack_bits(self, value: PortLike) -> Port:
        """View fixed-width words as consecutive MSB-first bits."""

        from claasp.domains import BinaryExtensionField, Bit, Word

        selection = as_selection(value)
        domain = selection.array_type.domain
        if not isinstance(domain, (Word, BinaryExtensionField)):
            raise ValueError("unpack_bits input must use a Word or binary-field domain")
        word_width = domain.width if isinstance(domain, Word) else domain.degree
        output_type = ArrayType(Bit(), (selection.array_type.unit_count * word_width,))
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
        output_type: ArrayType,
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

    def _resolve_selection(
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

    def _selection_bit_sources(self, selection: Selection) -> tuple[tuple[str, int], ...]:
        """Flatten a selection to the encoded bits of semantic graph sources."""

        values = {}
        ports = tuple(self._input_ports.values()) + tuple(
            component.output for component in self._components.values()
        )
        for port in ports:
            width = port.array_type.domain.encoded_bit_size
            if width is None:
                raise TypeError("graph wiring requires canonically encoded domains")
            units = []
            for position in range(port.array_type.unit_count):
                refs = tuple((port.owner_id, position * width + bit) for bit in range(width))
                units.append(refs[0] if width == 1 else refs)
            values[port.owner_id] = tuple(units)
        selected = self._resolve_selection(selection, values)
        return tuple(
            ref
            for unit in selected
            for ref in ((unit,) if len(unit) == 2 and isinstance(unit[0], str) else unit)
        )

    def _add_composite(
        self,
        definition,
        bindings: Mapping[str, PortLike],
        *,
        scope_id: str | None = None,
        primitive_round: Round | None = None,
    ):
        """Instantiate a reusable definition and lower its leaves into this graph."""

        from claasp.graph.composite import CompositeDefinition, CompositeInstance

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
        for name, array_type in definition.input_types:
            selection = as_selection(bindings[name])
            actual = self._port(selection.source.owner_id)
            if actual != selection.source:
                raise ValueError(f"binding {name!r} does not match its graph port type")
            if selection.array_type != array_type:
                raise ValueError(
                    f"binding {name!r} has type {selection.array_type!r}, expected {array_type!r}"
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
                output = self._add_component(component, primitive_round=target_round)
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

    def _set_output(self, output: PortLike | Sequence[PortLike]) -> None:
        """Declare the ordered logical units returned by this primitive."""

        if isinstance(output, Sequence) and not isinstance(output, (Port, Selection)):
            output = self._join(*output)
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
        if result.output is None or self._output is None:
            return None
        return self._encode_boundary(result.output, self._output.array_type)

    def evaluate_many(self, **inputs: object) -> tuple[int | tuple[int, ...] | None, ...]:
        """Evaluate named inputs, broadcasting scalar values across list inputs.

        A list supplies one value per evaluation. A scalar packed integer or a
        tuple of logical units is reused for every evaluation. All list inputs
        must have the same length.

        EXAMPLES::

            >>> from claasp.primitives import AES
            >>> aes = AES()
            >>> results = aes.evaluate_many(plaintext=[0, 1], key=0)
            >>> len(results)
            2
        """

        supplied = self._bind_inputs((), inputs)
        lengths = {len(value) for value in supplied.values() if isinstance(value, list)}
        if len(lengths) > 1:
            raise ValueError("all list inputs must have the same length")
        batch_size = lengths.pop() if lengths else 1
        return tuple(
            self.evaluate(
                {
                    name: value[index] if isinstance(value, list) else value
                    for name, value in supplied.items()
                }
            )
            for index in range(batch_size)
        )

    def evaluate_with_trace(self, *args: object, **kwargs: object):
        """Evaluate like :meth:`evaluate` and retain all intermediate values."""

        from claasp.representations.execution import ScalarExecutionDriver

        supplied = self._bind_inputs(args, kwargs)
        decoded = {
            name: self._decode_boundary(value, self._input_ports[name].array_type)
            for name, value in supplied.items()
        }
        return ScalarExecutionDriver().evaluate(self, decoded)

    @property
    def analysis(self) -> "Analysis":
        """Return the high-level analysis capabilities for this primitive."""

        from claasp.analysis import Analysis

        return Analysis(self)

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
    def _decode_boundary(value: object, array_type: ArrayType) -> tuple[int, ...]:
        from claasp.domains import Bit, PrimeField
        from claasp.encoding import bits_from_int, units_from_int

        if isinstance(value, int) and not isinstance(value, bool):
            if isinstance(array_type.domain, Bit):
                return bits_from_int(value, array_type.unit_count)
            if isinstance(array_type.domain, PrimeField):
                if array_type.unit_count != 1:
                    raise TypeError("prime-field vectors require a tuple of field elements")
                return (value,)
            width = array_type.domain.encoded_bit_size
            if width is not None:
                return units_from_int(value, width, array_type.unit_count)
        if isinstance(value, Sequence) and not isinstance(value, str):
            return tuple(value)
        raise TypeError("primitive inputs must be packed integers or sequences of logical units")

    @staticmethod
    def _encode_boundary(value: tuple[int, ...], array_type: ArrayType) -> int | tuple[int, ...]:
        from claasp.domains import Bit, PrimeField
        from claasp.encoding import int_from_bits, int_from_units

        if isinstance(array_type.domain, PrimeField):
            return value[0] if array_type.unit_count == 1 else value
        if isinstance(array_type.domain, Bit):
            return int_from_bits(value)
        width = array_type.domain.encoded_bit_size
        return value if width is None else int_from_units(value, width)


class PrimitiveBuilder:
    """Author a :class:`Primitive` through an explicitly mutable object.

    The finished primitive returned by :meth:`build` does not expose graph
    mutation as part of its public API.

    EXAMPLES::

        >>> from claasp import PrimitiveBuilder, ArrayType
        >>> from claasp.domains import Word
        >>> from claasp.components import Xor
        >>> bit = ArrayType(Word(1), (1,))
        >>> builder = PrimitiveBuilder("xor", {"left": bit, "right": bit})
        >>> builder.add_round()
        Round(number=0)
        >>> output = builder.add_component(Xor(builder.inputs()))
        >>> builder.set_output(output)
        >>> primitive = builder.build()
        >>> primitive.evaluate(0, 1)
        1
    """

    def __init__(
        self,
        family_name: str,
        inputs: Mapping[str, ArrayType | PrimitiveInput] | None = None,
        *,
        kind: PrimitiveKind | str | None = None,
        provenance: tuple[tuple[str, str], ...] = (),
        instance_name: str | None = None,
        round_count: int | None = None,
        **named_inputs: ArrayType | PrimitiveInput,
    ) -> None:
        if inputs is not None and named_inputs:
            raise TypeError("pass primitive inputs either as a mapping or as named arguments")
        inputs = named_inputs if inputs is None else inputs
        self._built = False
        self._inputs_declared = bool(inputs)
        self._infer_kind_from_inputs = kind is None
        primitive = object.__new__(Primitive)
        self._primitive = primitive
        Primitive.__init__(
            primitive,
            family_name,
            inputs,
            kind=kind,
            provenance=provenance,
            instance_name=instance_name,
            round_count=round_count,
            _builder=self,
        )

    @classmethod
    def _for_primitive(cls, primitive: Primitive) -> "PrimitiveBuilder":
        builder = object.__new__(cls)
        builder._primitive = primitive
        builder._built = False
        builder._inputs_declared = bool(primitive._input_ports)
        builder._infer_kind_from_inputs = False
        return builder

    def _ensure_open(self) -> None:
        if self._built:
            raise RuntimeError("this primitive builder has already been built")

    def input(self, selector: str | int) -> Port:
        """Return one input port for use in the graph being authored."""

        return self._primitive._input(selector)

    def set_inputs(
        self,
        inputs: Mapping[str, ArrayType | PrimitiveInput] | None = None,
        **named_inputs: ArrayType | PrimitiveInput,
    ) -> Sequence[Port]:
        """Declare the named inputs before graph construction and return their ports."""

        self._ensure_open()
        if inputs is not None and named_inputs:
            raise TypeError("pass primitive inputs either as a mapping or as named arguments")
        declarations = named_inputs if inputs is None else inputs
        if not isinstance(declarations, Mapping):
            raise TypeError("inputs must be a mapping from names to ArrayType objects")
        if not declarations:
            raise ValueError("set_inputs() requires at least one named input")
        if self._inputs_declared:
            raise RuntimeError("primitive inputs have already been declared")
        primitive = self._primitive
        if primitive._rounds or primitive._components or primitive._bindings or primitive._scopes:
            raise RuntimeError("primitive inputs must be declared before graph construction begins")
        descriptors, ports = _normalize_primitive_inputs(declarations)
        primitive._input_descriptors = descriptors
        primitive._input_ports = ports
        primitive._ports = dict(ports)
        if self._infer_kind_from_inputs:
            primitive._kind = infer_primitive_kind(descriptors)
        self._inputs_declared = True
        return tuple(ports.values())

    def inputs(self, *selectors: str | int) -> Sequence[Port]:
        """Return input ports in declaration or requested order."""

        return self._primitive._inputs(*selectors)

    def add_round(self) -> Round:
        """Append and return the next sequential round."""

        self._ensure_open()
        return self._primitive._add_round()

    def add_component(
        self,
        component: Component,
        *,
        primitive_round: Round | None = None,
    ) -> Port:
        """Validate and append a component, returning its output port."""

        self._ensure_open()
        return self._primitive._add_component(component, primitive_round=primitive_round)

    def add(
        self,
        component: Component,
        *,
        primitive_round: Round | None = None,
    ) -> Port:
        """Append ``component`` using the concise pseudocode-style spelling."""

        return self.add_component(component, primitive_round=primitive_round)

    def add_composite(
        self,
        definition,
        bindings: Mapping[str, PortLike],
        *,
        scope_id: str | None = None,
        primitive_round: Round | None = None,
    ):
        """Instantiate a reusable definition in the graph being authored."""

        self._ensure_open()
        return self._primitive._add_composite(
            definition,
            bindings,
            scope_id=scope_id,
            primitive_round=primitive_round,
        )

    def join(self, *values: PortLike) -> PortLike:
        """Join homogeneous values as structural wiring."""

        self._ensure_open()
        return self._primitive._join(*values)

    def pack_bits(self, value: PortLike, word_width: int, *, output_domain=None) -> Port:
        """View consecutive MSB-first bits as fixed-width words."""

        self._ensure_open()
        return self._primitive._pack_bits(value, word_width, output_domain=output_domain)

    def view(self, value: PortLike) -> Port:
        """Give an ordered selection a structural wiring boundary."""

        self._ensure_open()
        return self._primitive._view(value)

    def unpack_bits(self, value: PortLike) -> Port:
        """View fixed-width words as consecutive MSB-first bits."""

        self._ensure_open()
        return self._primitive._unpack_bits(value)

    def set_round_keys(self, round_keys: Iterable[object]) -> Sequence[object]:
        """Publish the graph's round keys."""

        self._ensure_open()
        return self._primitive._publish_round_keys(round_keys)

    def add_round_key(self, round_key: object) -> object:
        """Publish one round key in authoring order."""

        self._ensure_open()
        return self._primitive._publish_round_key(round_key)

    def set_intermediate_output(
        self,
        output: PortLike | Sequence[PortLike],
        *,
        name: str,
    ) -> object:
        """Publish one named inspectable output in the current round."""

        self._ensure_open()
        return self._primitive._set_intermediate_output(output, name=name)

    def set_round_output(self, *outputs: PortLike) -> object:
        """Publish the current round output as an intermediate named ``round_output``."""

        self._ensure_open()
        if not outputs:
            raise ValueError("round output must contain at least one value")
        output: PortLike | Sequence[PortLike] = outputs[0] if len(outputs) == 1 else outputs
        return self.set_intermediate_output(output, name="round_output")

    def set_key_schedule_states(self, states: Iterable[object]) -> Sequence[object]:
        """Publish the graph's key-schedule states."""

        self._ensure_open()
        return self._primitive._publish_key_schedule_states(states)

    def add_key_schedule_state(self, *values: object) -> object:
        """Publish one key-schedule state in authoring order."""

        self._ensure_open()
        return self._primitive._publish_key_schedule_state(*values)

    def set_output(self, output: PortLike | Sequence[PortLike]) -> None:
        """Declare the graph output without completing the builder."""

        self._ensure_open()
        self._primitive._set_output(output)

    def build(self, output: PortLike | Sequence[PortLike] | None = None) -> Primitive:
        """Return the completed primitive after an output has been declared."""

        self._ensure_open()
        if output is not None:
            self._primitive._set_output(output)
        if self._primitive._output is None:
            raise ValueError(
                "a primitive must have an output; pass an output to build() or call set_output()"
            )
        self._built = True
        return self._primitive
