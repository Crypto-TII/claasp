"""The fixed-length Salsa20 block function."""

from claasp.components import Constant, ModularAdd, Rotate, Xor
from claasp.graph import Primitive, PrimitiveKind, Selection, UnitArray, UnitArrayType, as_selection
from claasp.graph.metadata import public_input, secret_input
from claasp.unit_types import Word

PARAMETERS_CONFIGURATION_LIST = ({"number_of_rounds": 20},)
_WORD = UnitArrayType(Word(32), (1,))
_COLUMNS = ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11))
_ROWS = ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14))
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


class SalsaBlockFunction(Primitive):
    """Build one Salsa20 keystream block.

    The inputs are eight 32-bit key words, two nonce words, and two counter
    words. Each integer passed to :meth:`evaluate` packs those words from most
    significant to least significant; byte-oriented protocols should decode
    each word as little endian, as specified by Salsa20.

    EXAMPLES::

        >>> block = SalsaBlockFunction()
        >>> output = block.evaluate(key=0, nonce=0, counter=0)
        >>> f"{output:0128x}"[:16]
        '5bf6979a1b724c9b'
    """

    def __init__(self, number_of_rounds: int = 20) -> None:
        number_of_rounds = Primitive._validate_positive_integer(
            number_of_rounds,
            name="number_of_rounds",
        )
        key_type = UnitArrayType(Word(32), (8,))
        pair_type = UnitArrayType(Word(32), (2,))
        super().__init__(
            "salsa_block_function",
            {
                "key": secret_input(key_type),
                "nonce": public_input(pair_type, role="nonce"),
                "counter": public_input(pair_type, role="counter"),
            },
            kind=PrimitiveKind.BLOCK_FUNCTION,
            provenance=(("specification", "Salsa20 block function"),),
        )

        self._builder.add_round()
        constants = [
            self._builder.add_component(
                Constant(_WORD, (value,), component_id=f"constant_{index}")
            )[0]
            for index, value in enumerate(_SIGMA)
        ]
        key = self.graph.input("key")
        nonce = self.graph.input("nonce")
        counter = self.graph.input("counter")
        initial = [
            constants[0],
            key[0],
            key[1],
            key[2],
            key[3],
            constants[1],
            nonce[0],
            nonce[1],
            counter[0],
            counter[1],
            constants[2],
            key[4],
            key[5],
            key[6],
            key[7],
            constants[3],
        ]
        state = list(initial)
        for round_number in range(number_of_rounds):
            if round_number:
                self._builder.add_round()
            groups = _COLUMNS if round_number % 2 == 0 else _ROWS
            for quarter_number, (a, b, c, d) in enumerate(groups):
                state[a], state[b], state[c], state[d] = self._quarter_round(
                    state[a],
                    state[b],
                    state[c],
                    state[d],
                    f"round_{round_number}_quarter_{quarter_number}",
                )
            self._builder.set_round_output(*state)

        self._builder.add_round()
        output = [
            self._builder.add_component(
                ModularAdd((before, after), component_id=f"feed_forward_{index}")
            )
            for index, (before, after) in enumerate(zip(initial, state))
        ]
        self._builder.set_output(output)

    def _quarter_round(
        self,
        a: UnitArray | Selection,
        b: UnitArray | Selection,
        c: UnitArray | Selection,
        d: UnitArray | Selection,
        prefix: str,
    ):
        b = self._add_rotate_xor(a, d, b, 7, f"{prefix}_step_0")
        c = self._add_rotate_xor(a, b, c, 9, f"{prefix}_step_1")
        d = self._add_rotate_xor(b, c, d, 13, f"{prefix}_step_2")
        a = self._add_rotate_xor(c, d, a, 18, f"{prefix}_step_3")
        return a, b, c, d

    def _add_rotate_xor(
        self,
        left: UnitArray | Selection,
        right: UnitArray | Selection,
        destination: UnitArray | Selection,
        rotation: int,
        prefix: str,
    ) -> UnitArray:
        added = self._builder.add_component(
            ModularAdd(
                (as_selection(left), as_selection(right)),
                component_id=f"{prefix}_add",
            )
        )
        rotated = self._builder.add_component(
            Rotate(added, rotation, "left", component_id=f"{prefix}_rotate")
        )
        return self._builder.add_component(Xor(destination, rotated, component_id=f"{prefix}_xor"))


__all__ = ["PARAMETERS_CONFIGURATION_LIST", "SalsaBlockFunction"]
