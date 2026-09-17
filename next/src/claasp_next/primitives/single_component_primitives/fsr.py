"""One-component feedback-register primitive."""

from claasp_next.components import FeedbackRegister, FeedbackRegisterSpec, FeedbackTerm
from claasp_next.domains import BinaryExtensionField, Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import first_irreducible, positive


class Fsr(Primitive):
    def __init__(self, register_size: int = 4, description=None) -> None:
        register_size = positive(register_size, "register_size")
        if description is None:
            description = [[[register_size, [[0], [1]]]], 1]
        if not isinstance(description, (list, tuple)) or len(description) not in (2, 3):
            raise ValueError("description must contain registers, word width, and optional clocks")
        legacy_registers, word_width = description[:2]
        clocks = 1 if len(description) == 2 else description[2]
        word_width = positive(word_width, "description word width")
        domain = Bit() if word_width == 1 else BinaryExtensionField(
            word_width, first_irreducible(word_width)
        )
        if register_size % word_width:
            raise ValueError("register_size must be divisible by the description word width")

        def terms(polynomial):
            if polynomial == []:
                return (FeedbackTerm((), 1),)
            if word_width == 1:
                return tuple(FeedbackTerm(tuple(monomial)) for monomial in polynomial)
            return tuple(FeedbackTerm(tuple(monomial[1]), monomial[0]) for monomial in polynomial)

        specs = []
        for legacy_register in legacy_registers:
            if len(legacy_register) not in (2, 3):
                raise ValueError("each register needs a length, feedback, and optional clock")
            clock = None if len(legacy_register) == 2 else terms(legacy_register[2])
            specs.append(FeedbackRegisterSpec(legacy_register[0], terms(legacy_register[1]), clock))
        if sum(spec.length for spec in specs) != register_size // word_width:
            raise ValueError("description register lengths do not cover register_size")
        super().__init__(
            "fsr", {"input": ValueType(domain, (register_size // word_width,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(self.add_component(FeedbackRegister(
            self.input("input"), tuple(specs), clocks
        )))


__all__ = ["Fsr"]
