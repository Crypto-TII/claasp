from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.domains import BinaryExtensionField, Bit
from claasp_next.graph import Component, PortLike
from claasp_next.graph.port import as_selection
from claasp_next.utils.finite_fields import first_irreducible_polynomial


@dataclass(frozen=True, slots=True, init=False)
class FeedbackTerm:
    """One coefficient times a monomial in global register positions."""

    positions: tuple[int, ...]
    coefficient: int = 1

    def __init__(self, positions: Iterable[int] | int = (), coefficient: int = 1) -> None:
        frozen_positions = (positions,) if isinstance(positions, int) else tuple(positions)
        if any(
            not isinstance(position, int) or isinstance(position, bool) or position < 0
            for position in frozen_positions
        ):
            raise ValueError("feedback positions must be non-negative integers")
        if not isinstance(coefficient, int) or isinstance(coefficient, bool):
            raise TypeError("feedback coefficient must be an integer")
        object.__setattr__(self, "positions", frozen_positions)
        object.__setattr__(self, "coefficient", coefficient)


@dataclass(frozen=True, slots=True, init=False)
class FeedbackRegisterSpec:
    """Length, feedback polynomial, and optional Boolean clock polynomial."""

    length: int
    feedback: tuple[FeedbackTerm, ...]
    clock: tuple[FeedbackTerm, ...] | None = None

    def __init__(
        self,
        length: int,
        feedback: Iterable[FeedbackTerm],
        clock: Iterable[FeedbackTerm] | None = None,
    ) -> None:
        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError("register length must be an integer")
        if length <= 0:
            raise ValueError("register length must be positive")
        frozen_feedback = tuple(feedback)
        if not frozen_feedback:
            raise ValueError("register feedback must contain at least one term")
        if any(not isinstance(term, FeedbackTerm) for term in frozen_feedback):
            raise TypeError("register feedback entries must be FeedbackTerm values")
        frozen_clock = None if clock is None else tuple(clock)
        if frozen_clock is not None:
            if not frozen_clock:
                raise ValueError("register clock must be None or non-empty")
            if any(not isinstance(term, FeedbackTerm) for term in frozen_clock):
                raise TypeError("register clock entries must be FeedbackTerm values")
        object.__setattr__(self, "length", length)
        object.__setattr__(self, "feedback", frozen_feedback)
        object.__setattr__(self, "clock", frozen_clock)


@dataclass(frozen=True, slots=True, init=False)
class FeedbackRegisterParameters:
    """Validated domain and register parameters for one feedback component."""

    domain: Bit | BinaryExtensionField
    registers: tuple[FeedbackRegisterSpec, ...]
    clocks: int = 1

    def __init__(
        self,
        domain: Bit | BinaryExtensionField,
        registers: Iterable[FeedbackRegisterSpec],
        clocks: int = 1,
    ) -> None:
        frozen_registers = tuple(registers)
        if not isinstance(domain, (Bit, BinaryExtensionField)):
            raise TypeError("feedback-register domain must be Bit or BinaryExtensionField")
        if not frozen_registers or any(
            not isinstance(register, FeedbackRegisterSpec)
            for register in frozen_registers
        ):
            raise TypeError("registers must contain FeedbackRegisterSpec values")
        if not isinstance(clocks, int) or isinstance(clocks, bool) or clocks <= 0:
            raise ValueError("clock count must be a positive integer")
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "registers", frozen_registers)
        object.__setattr__(self, "clocks", clocks)

    @property
    def unit_count(self) -> int:
        return sum(register.length for register in self.registers)

    @classmethod
    def from_taps(
        cls,
        register_size: int,
        taps: Iterable[int],
        *,
        word_width: int = 1,
        clocks: int = 1,
    ) -> "FeedbackRegisterParameters":
        """Describe one Fibonacci register from its feedback tap positions."""

        if not isinstance(register_size, int) or isinstance(register_size, bool) or register_size <= 0:
            raise ValueError("register_size must be a positive integer")
        if not isinstance(word_width, int) or isinstance(word_width, bool) or word_width <= 0:
            raise ValueError("word_width must be a positive integer")
        if register_size % word_width:
            raise ValueError("register_size must be divisible by word_width")
        domain = Bit() if word_width == 1 else BinaryExtensionField(
            word_width, first_irreducible_polynomial(word_width),
        )
        feedback = [FeedbackTerm(tap) for tap in taps]
        return cls(
            domain,
            [FeedbackRegisterSpec(register_size // word_width, feedback)],
            clocks,
        )

@dataclass(frozen=True, slots=True, init=False)
class FeedbackRegister(Component):
    """Clock one or more contiguous binary or binary-field word registers."""

    registers: tuple[FeedbackRegisterSpec, ...]
    clocks: int

    def __init__(
        self,
        component_input: PortLike,
        registers: Iterable[FeedbackRegisterSpec],
        clocks: int = 1,
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        registers = tuple(registers)
        domain = component_input.value_type.domain
        if not isinstance(domain, (Bit, BinaryExtensionField)):
            raise ValueError("feedback registers require Bit or BinaryExtensionField units")
        if not registers:
            raise ValueError("feedback registers require at least one register spec")
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
