"""Validated typed cipher graph."""

from collections.abc import Mapping, Sequence
from copy import copy
import re

from claasp_next.core.component import Component
from claasp_next.core.port import Port, PortLike, Selection, as_selection
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
        target_round = self._rounds[-1] if cipher_round is None else cipher_round
        if component.component_id is None:
            kind = re.sub(r"(?<!^)(?=[A-Z])", "_", type(component).__name__).lower()
            generated_id = f"{kind}_{target_round.number}_{len(target_round.components)}"
            component = copy(component)
            object.__setattr__(component, "component_id", generated_id)
        if component.component_id in self._ports:
            raise ValueError(f"graph source {component.component_id!r} already exists")

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

    def set_output(self, output: PortLike) -> None:
        """Declare the ordered logical units returned by this cipher."""

        output = as_selection(output)
        try:
            actual_port = self._ports[output.source.owner_id]
        except KeyError as error:
            raise ValueError("output source is not available in this graph") from error
        if output.source != actual_port:
            raise ValueError("output source does not match its graph port type")
        self._output = output

    def evaluate(self, *args: object, **kwargs: object) -> int | tuple[int, ...] | None:
        """Evaluate with convenient boundary encoding and return the cipher output.

        Inputs may be supplied as one mapping, as keyword arguments, or in the
        cipher's declared input order. Bit, byte/extension-field, and word
        vectors accept packed integers and produce a packed integer output.
        """

        result = self.evaluate_with_trace(*args, **kwargs)
        if result.output is None or self.output is None:
            return None
        return self._encode_boundary(result.output, self.output.value_type)

    def evaluate_with_trace(self, *args: object, **kwargs: object):
        """Evaluate like :meth:`evaluate` and retain all intermediate values."""

        from claasp_next.evaluators import ScalarEvaluator

        supplied = self._bind_inputs(args, kwargs)
        decoded = {
            name: self._decode_boundary(value, self._input_ports[name].value_type)
            for name, value in supplied.items()
        }
        return ScalarEvaluator().evaluate(self, decoded)

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
            raise ValueError(f"cipher inputs do not match: missing={missing}, unexpected={unexpected}")
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
        raise TypeError("cipher inputs must be packed integers or sequences of logical units")

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
