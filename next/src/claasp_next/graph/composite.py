"""Immutable reusable graph compositions and their instantiated scopes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from claasp_next.graph.component import Component
from claasp_next.graph.binding import ValueBinding
from claasp_next.graph.port import Port, PortLike, Selection, as_selection
from claasp_next.graph.value_type import ValueType


class CompositeOutputs(Sequence[Selection]):
    """Ordered composite outputs with optional access by semantic name."""

    def __init__(self, outputs: tuple[tuple[str, Selection], ...]) -> None:
        self._outputs = outputs
        self._by_name = dict(outputs)

    def __len__(self) -> int:
        return len(self._outputs)

    def __getitem__(self, key: int | slice | str):
        if isinstance(key, str):
            try:
                return self._by_name[key]
            except KeyError as error:
                raise KeyError(f"composite output {key!r} does not exist") from error
        values = tuple(value for _, value in self._outputs)
        return values[key]

    def __call__(self, name: str = "output") -> Selection:
        return self[name]


@dataclass(frozen=True, slots=True)
class CompositeTemplate:
    """A nested scope retained inside a composite definition."""

    path: str
    definition: "CompositeDefinition"
    input_bindings: tuple[tuple[str, Selection], ...]
    output_bindings: tuple[tuple[str, Selection], ...]
    component_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompositeDefinition:
    """An immutable typed graph recipe with named inputs and outputs.

    The recipe contains only ordinary leaf components.  Execution and model
    generation consume :meth:`as_primitive`; instantiation additionally keeps
    a hierarchical scope overlay on the parent graph.
    """

    name: str
    input_types: tuple[tuple[str, ValueType], ...]
    rounds: tuple[tuple[Component, ...], ...]
    bindings: tuple[ValueBinding, ...]
    outputs: tuple[tuple[str, Selection], ...]
    provenance: tuple[tuple[str, str], ...] = ()
    nested_scopes: tuple[CompositeTemplate, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("composite name must be a non-empty string")
        input_names = tuple(name for name, _ in self.input_types)
        output_names = tuple(name for name, _ in self.outputs)
        if not input_names or len(set(input_names)) != len(input_names):
            raise ValueError("composite input names must be non-empty and unique")
        if not output_names or len(set(output_names)) != len(output_names):
            raise ValueError("composite output names must be non-empty and unique")
        if any(not isinstance(value_type, ValueType) for _, value_type in self.input_types):
            raise TypeError("composite inputs must have ValueType objects")

    @property
    def inputs(self) -> Mapping[str, ValueType]:
        return dict(self.input_types)

    @property
    def named_outputs(self) -> Mapping[str, Selection]:
        return dict(self.outputs)

    @property
    def output(self) -> CompositeOutputs:
        return CompositeOutputs(self.outputs)

    def as_primitive(self, output: str = "output"):
        """Project this definition to a standalone flat primitive graph."""

        from copy import copy

        from claasp_next.graph.primitive import Primitive

        primitive = Primitive(self.name, dict(self.input_types), provenance=self.provenance)
        for binding in self.bindings:
            primitive._add_binding(
                binding.kind, binding.inputs, binding.output_type,
                word_width=binding.word_width, binding_id=binding.binding_id,
                _validate_inputs=False,
            )
        for components in self.rounds:
            primitive.add_round()
            for component in components:
                primitive.add_component(copy(component))
        primitive.set_output(self.output(output))
        return primitive

    def evaluate(self, *args: object, output: str = "output", **kwargs: object):
        """Evaluate one named output through the ordinary scalar representation."""

        return self.as_primitive(output).evaluate(*args, **kwargs)

    def analyze(self, output: str = "output"):
        """Return the ordinary analysis facade for one named output."""

        return self.as_primitive(output).analyze()


@dataclass(frozen=True, slots=True)
class CompositeInstance:
    """A composite definition bound to a named scope in a parent graph."""

    path: str
    definition: CompositeDefinition
    input_bindings: tuple[tuple[str, Selection], ...]
    output_bindings: tuple[tuple[str, Selection], ...]
    component_ids: tuple[str, ...]
    _primitive: object = field(repr=False, compare=False)

    @property
    def inputs(self) -> Mapping[str, Selection]:
        return dict(self.input_bindings)

    @property
    def outputs(self) -> Mapping[str, Selection]:
        return dict(self.output_bindings)

    @property
    def components(self) -> tuple[Component, ...]:
        return tuple(self._primitive.component(component_id) for component_id in self.component_ids)

    @property
    def output(self) -> CompositeOutputs:
        return CompositeOutputs(self.output_bindings)

    def scope(self, relative_path: str) -> "CompositeInstance":
        return self._primitive.scope(f"{self.path}/{relative_path}")

    def as_primitive(self, output: str = "output"):
        """Project this scope's reusable definition to a standalone graph."""

        return self.definition.as_primitive(output)

    def evaluate(self, *args: object, output: str = "output", **kwargs: object):
        return self.definition.evaluate(*args, output=output, **kwargs)

    def value_from(self, evaluation, output: str = "output") -> tuple[int, ...]:
        """Read one named scope output from a parent-graph evaluation result."""

        selection = self.output(output)
        value = evaluation.value_of(selection.source.owner_id)
        return tuple(value[position] for position in selection.positions)

    def analyze(self, output: str = "output"):
        return self.definition.analyze(output)


class CompositeBuilder:
    """Author a reusable composite with the ordinary typed graph API."""

    def __init__(self, name: str, inputs: Mapping[str, ValueType]) -> None:
        from claasp_next.graph.primitive import Primitive

        self._primitive = Primitive(name, inputs)
        self._outputs: dict[str, Selection] = {}

    @property
    def name(self) -> str:
        return self._primitive.family_name

    @property
    def input_ports(self) -> Mapping[str, Port]:
        return self._primitive.input_ports

    def inputs(self, *selectors: str | int) -> Sequence[Port]:
        return self._primitive.inputs(*selectors)

    def input(self, selector: str | int) -> Port:
        return self._primitive.input(selector)

    def add_round(self):
        return self._primitive.add_round()

    def add_component(self, component: Component, *, primitive_round=None) -> Port:
        return self._primitive.add_component(component, primitive_round=primitive_round)

    def add_composite(self, definition: CompositeDefinition, bindings: Mapping[str, PortLike], **kwargs):
        return self._primitive.add_composite(definition, bindings, **kwargs)

    def join(self, *values: PortLike) -> PortLike:
        """Join values through the graph's normalized structural wiring."""

        return self._primitive.join(*values)

    def pack_bits(self, value: PortLike, word_width: int, *, output_domain=None) -> Port:
        return self._primitive.pack_bits(value, word_width, output_domain=output_domain)

    def unpack_bits(self, value: PortLike) -> Port:
        return self._primitive.unpack_bits(value)

    def set_output(self, name: str, output: PortLike | Sequence[PortLike]) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("composite output name must be a non-empty string")
        if name in self._outputs:
            raise ValueError(f"composite output {name!r} already exists")
        if isinstance(output, Sequence) and not isinstance(output, (Port, Selection)):
            output = self.join(*output)
        selection = as_selection(output)
        actual = self._primitive.port(selection.source.owner_id)
        if actual != selection.source:
            raise ValueError("output source does not match its graph port type")
        self._outputs[name] = selection

    def build(self, *, provenance: Mapping[str, str] | None = None) -> CompositeDefinition:
        if not self._outputs:
            raise ValueError("a composite must declare at least one named output")
        templates = tuple(
            CompositeTemplate(
                instance.path,
                instance.definition,
                instance.input_bindings,
                instance.output_bindings,
                instance.component_ids,
            )
            for instance in self._primitive.scopes
        )
        return CompositeDefinition(
            name=self.name,
            input_types=tuple((name, port.value_type) for name, port in self.input_ports.items()),
            rounds=tuple(tuple(primitive_round.components) for primitive_round in self._primitive.rounds),
            bindings=self._primitive.bindings,
            outputs=tuple(self._outputs.items()),
            provenance=tuple(sorted((provenance or {}).items())),
            nested_scopes=templates,
        )
