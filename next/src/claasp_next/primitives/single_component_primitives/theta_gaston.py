"""One-component Gaston theta permutation."""

from claasp_next.components.permutation import gaston_theta
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class ThetaGaston(Primitive):
    def __init__(self, bit_size: int = 320, rotation_amounts_parameter=None) -> None:
        amounts = (
            (1, 18, 23, 25, 32, 52, 60, 63)
            if rotation_amounts_parameter is None
            else tuple(rotation_amounts_parameter)
        )
        super().__init__(
            "theta_gaston", {"input": ValueType(Bit(), (positive(bit_size, "bit_size"),))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(gaston_theta(self.input("input"), amounts)))


__all__ = ["ThetaGaston"]
