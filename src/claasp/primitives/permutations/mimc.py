"""Minimal native-prime-field MiMC permutation."""

from collections.abc import Iterable

from claasp.components import Add, Constant, Power
from claasp.domains import PrimeField
from claasp.graph import Primitive, ValueType


class MiMC(Primitive):
    """Iterate ``x <- (x + c_i)^exponent`` over ``GF(modulus)``.

    EXAMPLES::

        >>> from claasp.primitives import MiMC
        >>> from claasp.primitives import MiMC
        >>> primitive = MiMC(17, 3, (1, 2, 4))
        >>> len(primitive.graph.rounds)
        3
        >>> primitive.evaluate(5)
        5

    These are teaching parameters, not a secure parameter set.
    """

    def __init__(self, modulus: int, exponent: int, round_constants: Iterable[int]) -> None:
        field = PrimeField(modulus)
        scalar_type = ValueType(field, (1,))
        constants = tuple(round_constants)
        if not constants:
            raise ValueError("MiMC requires at least one round constant")

        super().__init__("mimc", {"state": scalar_type})
        state = self.graph.input("state")
        for round_number, round_constant in enumerate(constants):
            self._builder.add_round()
            constant = Constant(
                scalar_type, (round_constant,), component_id=f"constant_{round_number}_0"
            )
            constant_output = self._builder.add_component(constant)
            addition = Add((state, constant_output), component_id=f"add_{round_number}_1")
            addition_output = self._builder.add_component(addition)
            power = Power(addition_output, exponent, component_id=f"power_{round_number}_2")
            state = self._builder.add_component(power)

        self._builder.set_output(state)
