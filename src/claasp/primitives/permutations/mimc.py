"""Minimal native-prime-field MiMC permutation."""

from collections.abc import Iterable

from claasp._catalogue_metadata import _entry
from claasp.components import Add, Constant, Power
from claasp.graph import Primitive, UnitArrayType
from claasp.unit_types import PrimeField


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

    Round states are published at their original graph indices and can be
    used for slicing. This does not enable XOR-trail models over prime fields::

        >>> tuple(index for index, _ in primitive.graph.round_output_boundaries)
        (0, 1, 2)
        >>> from claasp.transformations import slice_rounds
        >>> prefix = slice_rounds(primitive, 0, 0).primitive
        >>> suffix = slice_rounds(primitive, 1, 2).primitive
        >>> suffix.evaluate(state=prefix.evaluate(state=5))
        5

    These are teaching parameters, not a secure parameter set.
    """

    def __init__(self, modulus: int, exponent: int, round_constants: Iterable[int]) -> None:
        field = PrimeField(modulus)
        scalar_type = UnitArrayType(field, (1,))
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

            self._builder.set_round_output(state)
        self._builder.set_output(state)


__catalogue__ = (
    _entry(
        "primitive",
        MiMC,
        evidence=("tests/unit/primitives/permutations/test_mimc.py",),
        example={"modulus": 17, "exponent": 3, "round_constants": (1, 2, 4)},
    ),
)
