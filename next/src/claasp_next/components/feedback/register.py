from dataclasses import dataclass

from claasp_next.domains import BinaryExtensionField, Bit
from claasp_next.graph import Component, PortLike
from claasp_next.graph.port import as_selection


@dataclass(frozen=True, slots=True)
class FeedbackTerm:
    """One coefficient times a monomial in global register positions."""

    positions: tuple[int, ...]
    coefficient: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.positions, tuple) or any(
            not isinstance(position, int) or isinstance(position, bool) or position < 0
            for position in self.positions
        ):
            raise ValueError("feedback positions must be a tuple of non-negative integers")
        if not isinstance(self.coefficient, int) or isinstance(self.coefficient, bool):
            raise TypeError("feedback coefficient must be an integer")


@dataclass(frozen=True, slots=True)
class FeedbackRegisterSpec:
    """Length, feedback polynomial, and optional Boolean clock polynomial."""

    length: int
    feedback: tuple[FeedbackTerm, ...]
    clock: tuple[FeedbackTerm, ...] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.length, int) or isinstance(self.length, bool):
            raise TypeError("register length must be an integer")
        if self.length <= 0:
            raise ValueError("register length must be positive")
        if not isinstance(self.feedback, tuple) or not self.feedback:
            raise ValueError("register feedback must contain at least one term")
        if any(not isinstance(term, FeedbackTerm) for term in self.feedback):
            raise TypeError("register feedback entries must be FeedbackTerm values")
        if self.clock is not None:
            if not isinstance(self.clock, tuple) or not self.clock:
                raise ValueError("register clock must be None or a non-empty tuple")
            if any(not isinstance(term, FeedbackTerm) for term in self.clock):
                raise TypeError("register clock entries must be FeedbackTerm values")


@dataclass(frozen=True, slots=True, init=False)
class FeedbackRegister(Component):
    """Clock one or more contiguous binary or binary-field word registers."""

    registers: tuple[FeedbackRegisterSpec, ...]
    clocks: int

    def __init__(
        self,
        component_input: PortLike,
        registers: tuple[FeedbackRegisterSpec, ...],
        clocks: int = 1,
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        domain = component_input.value_type.domain
        if not isinstance(domain, (Bit, BinaryExtensionField)):
            raise ValueError("feedback registers require Bit or BinaryExtensionField units")
        if not isinstance(registers, tuple) or not registers:
            raise ValueError("feedback registers require a non-empty tuple of register specs")
        if any(not isinstance(register, FeedbackRegisterSpec) for register in registers):
            raise TypeError("registers must contain FeedbackRegisterSpec values")
        if sum(register.length for register in registers) != component_input.value_type.unit_count:
            raise ValueError("register lengths must cover every input unit exactly")
        if not isinstance(clocks, int) or isinstance(clocks, bool):
            raise TypeError("clock count must be an integer")
        if clocks <= 0:
            raise ValueError("clock count must be positive")
        unit_count = component_input.value_type.unit_count
        for register in registers:
            terms = register.feedback + (() if register.clock is None else register.clock)
            for term in terms:
                domain.validate(term.coefficient)
                if any(position >= unit_count for position in term.positions):
                    raise ValueError("feedback position lies outside the register state")
            if register.clock is not None and not isinstance(domain, Bit):
                raise ValueError("conditional register clocks require the Bit domain")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        object.__setattr__(self, "registers", registers)
        object.__setattr__(self, "clocks", clocks)
        Component.__post_init__(self)
