"""Validated typed cipher graph."""

from collections.abc import Mapping

from claasp_next.core.component import Component
from claasp_next.core.port import Port, Selection
from claasp_next.core.round import Round
from claasp_next.core.value_type import ValueType


class Cipher:
    """A round-oriented directed acyclic graph of typed components."""

    def __init__(self, family_name: str, inputs: Mapping[str, ValueType]) -> None:
        if not isinstance(family_name, str):
            raise TypeError("family_name must be a string")
        if not family_name:
            raise ValueError("family_name must not be empty")
        if not isinstance(inputs, Mapping):
            raise TypeError("inputs must be a mapping from names to ValueType objects")
        if not inputs:
            raise ValueError("a cipher must declare at least one input")

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
        self._input_ports = ports
        self._ports = dict(ports)
        self._rounds: list[Round] = []
        self._components: dict[str, Component] = {}
        self._output: Selection | None = None

    @property
    def family_name(self) -> str:
        return self._family_name

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
    def output(self) -> Selection | None:
        return self._output

    def input(self, name: str) -> Port:
        try:
            return self._input_ports[name]
        except KeyError as error:
            raise KeyError(f"cipher input {name!r} does not exist") from error

    def port(self, owner_id: str) -> Port:
        try:
            return self._ports[owner_id]
        except KeyError as error:
            raise KeyError(f"graph source {owner_id!r} does not exist") from error

    def add_round(self) -> Round:
        cipher_round = Round(len(self._rounds))
        self._rounds.append(cipher_round)
        return cipher_round

    def add_component(self, component: Component, *, cipher_round: Round | None = None) -> Port:
        """Validate and append a component, returning its output port."""

        if not isinstance(component, Component):
            raise TypeError("component must be a Component")
        if not self._rounds:
            raise ValueError("add a round before adding components")
        if component.component_id in self._ports:
            raise ValueError(f"graph source {component.component_id!r} already exists")

        target_round = self._rounds[-1] if cipher_round is None else cipher_round
        if not any(target_round is existing_round for existing_round in self._rounds):
            raise ValueError("target round does not belong to this cipher")
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

    def set_output(self, output: Selection) -> None:
        """Declare the ordered logical units returned by this cipher."""

        if not isinstance(output, Selection):
            raise TypeError("output must be a Selection")
        try:
            actual_port = self._ports[output.source.owner_id]
        except KeyError as error:
            raise ValueError("output source is not available in this graph") from error
        if output.source != actual_port:
            raise ValueError("output source does not match its graph port type")
        self._output = output
