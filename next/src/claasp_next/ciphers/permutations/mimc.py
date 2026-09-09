"""Minimal native-prime-field MiMC permutation."""

from collections.abc import Iterable

from claasp_next.components import Add, Constant, Power
from claasp_next.core import Cipher, ValueType
from claasp_next.domains import PrimeField


class MiMCPermutation(Cipher):
    """Iterate ``x <- (x + c_i)^exponent`` over ``GF(modulus)``.

    EXAMPLES::

        >>> from claasp_next.ciphers import MiMCPermutation
        >>> from claasp_next.evaluators import ScalarEvaluator
        >>> cipher = MiMCPermutation(17, 3, (1, 2, 4))
        >>> len(cipher.rounds)
        3
        >>> ScalarEvaluator().evaluate(cipher, {"state": (5,)}).output
        (5,)

    These are teaching parameters, not a secure parameter set.
    """

    def __init__(self, modulus: int, exponent: int, round_constants: Iterable[int]) -> None:
        field = PrimeField(modulus)
        scalar_type = ValueType(field, (1,))
        constants = tuple(round_constants)
        if not constants:
            raise ValueError("MiMC requires at least one round constant")

        super().__init__("mimc", {"state": scalar_type})
        state = self.input("state")
        for round_number, round_constant in enumerate(constants):
            self.add_round()
            constant = Constant(f"constant_{round_number}_0", scalar_type, (round_constant,))
            constant_output = self.add_component(constant)
            addition = Add(
                f"add_{round_number}_1",
                (state.select_all(), constant_output.select_all()),
            )
            addition_output = self.add_component(addition)
            power = Power(f"power_{round_number}_2", addition_output.select_all(), exponent)
            state = self.add_component(power)

        self.set_output(state.select_all())
