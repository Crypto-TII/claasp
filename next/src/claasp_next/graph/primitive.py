"""Validated typed primitive graph."""

from collections.abc import Mapping, Sequence
from copy import copy
import re

from claasp_next.graph.component import Component
from claasp_next.graph.port import Port, PortLike, Selection, as_selection
from claasp_next.graph.round import Round
from claasp_next.graph.value_type import ValueType


class Primitive:
    """A round-oriented directed acyclic graph of typed components."""

    def __init__(
        self,
        family_name: str,
        inputs: Mapping[str, ValueType],
        *,
        provenance: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if not isinstance(family_name, str):
            raise TypeError("family_name must be a string")
        if not family_name:
            raise ValueError("family_name must not be empty")
        if not isinstance(inputs, Mapping):
            raise TypeError("inputs must be a mapping from names to ValueType objects")
        ports: dict[str, Port] = {}
        for name, value_type in inputs.items():
            if not isinstance(name, str):
                raise TypeError("input names must be strings")
            if not name:
                raise ValueError("input names must not be empty")
            if not isinstance(value_type, ValueType):
                raise TypeError(f"input {name!r} must have a ValueType")
            ports[name] = Port(name, value_type)

        self._family_name = family_name
        self._provenance = tuple(provenance)
        self._input_ports = ports
        self._ports = dict(ports)
        self._rounds: list[Round] = []
        self._components: dict[str, Component] = {}
        self._scopes: dict[str, object] = {}
        self._output: Selection | None = None

    @property
    def family_name(self) -> str:
        return self._family_name

    @property
    def provenance(self) -> tuple[tuple[str, str], ...]:
        """Stable identity and derivation metadata for this graph."""

        return self._provenance

    @property
    def inputs(self) -> Mapping[str, Port]:
        return dict(self._input_ports)

    @property
    def rounds(self) -> tuple[Round, ...]:
        return tuple(self._rounds)

    @property
    def components(self) -> tuple[Component, ...]:
        return tuple(self._components.values())

    @property
    def scopes(self) -> tuple[object, ...]:
        """Composite instances in deterministic path order."""

        return tuple(self._scopes.values())

    @property
    def output(self) -> Selection | None:
        return self._output

    def input(self, name: str) -> Port:
        try:
            return self._input_ports[name]
        except KeyError as error:
            raise KeyError(f"primitive input {name!r} does not exist") from error

    def port(self, owner_id: str) -> Port:
        try:
            return self._ports[owner_id]
        except KeyError as error:
            raise KeyError(f"graph source {owner_id!r} does not exist") from error

    def component(self, component_id: str) -> Component:
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
                raise ValueError(f"input source {source_id!r} is not available in this graph") from error
            if component_input.source != actual_port:
                raise ValueError(f"input source {source_id!r} does not match its graph port type")

        target_round._append(component)
        self._components[component.component_id] = component
        self._ports[component.component_id] = component.output
        return component.output

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
            raise ValueError(f"composite bindings do not match: missing={missing}, unexpected={unexpected}")

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

        def remap(selection: Selection) -> Selection:
            source = remapped[selection.source.owner_id]
            return source[selection.positions]

        component_ids: list[str] = []
        for components in definition.rounds:
            for template_component in components:
                component = copy(template_component)
                local_id = template_component.component_id
                if local_id is None:
                    raise ValueError("composite definitions must contain assigned component identifiers")
                component_id = f"{scope_id}/{local_id}"
                object.__setattr__(component, "component_id", component_id)
                object.__setattr__(component, "inputs", tuple(remap(item) for item in component.inputs))
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

    def set_output(self, output: PortLike) -> None:
        """Declare the ordered logical units returned by this primitive."""

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

    def diagram(self, annotation=None):
        """Compile this graph and an optional trace or trail to diagram IR."""

        from claasp_next.annotations import GraphAnnotation
        from claasp_next.representations.diagrams import DiagramCompiler

        if annotation is not None and not isinstance(annotation, GraphAnnotation) and hasattr(annotation, "annotate"):
            annotation = annotation.annotate(self)
        return DiagramCompiler().compile(self, annotation)

    def draw(self, format: str = "ascii", annotation=None):
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

    def _bind_inputs(self, args: tuple[object, ...], kwargs: Mapping[str, object]) -> Mapping[str, object]:
        if kwargs and args:
            raise TypeError("use positional arguments, keyword arguments, or one mapping; do not mix them")
        if kwargs:
            supplied = dict(kwargs)
        elif len(args) == 1 and isinstance(args[0], Mapping):
            supplied = dict(args[0])
        else:
            if len(args) != len(self._input_ports):
                raise TypeError(f"expected {len(self._input_ports)} positional inputs, got {len(args)}")
            supplied = dict(zip(self._input_ports, args))
        expected = set(self._input_ports)
        if set(supplied) != expected:
            missing = sorted(expected - set(supplied))
            unexpected = sorted(set(supplied) - expected)
            raise ValueError(f"primitive inputs do not match: missing={missing}, unexpected={unexpected}")
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
