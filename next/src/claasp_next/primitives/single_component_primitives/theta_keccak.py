"""One-component Keccak theta permutation."""

from claasp_next.components.permutation import keccak_theta
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class ThetaKeccak(Primitive):
    def __init__(self, bit_size: int = 25) -> None:
        super().__init__(
            "theta_keccak", {"input": ValueType(Bit(), (positive(bit_size, "bit_size"),))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(keccak_theta(self.input("input"))))


__all__ = ["ThetaKeccak"]
