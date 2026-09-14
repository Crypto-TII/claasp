"""The fixed-length Salsa permutation."""

from claasp_next.components import Concatenate, ModularAdd, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.graph import Primitive, Port, Selection, ValueType


_COLUMNS = ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11))
_ROWS = ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14))


class Salsa(Primitive):
    """Build the word-oriented Salsa permutation.

    One round applies four complete quarter rounds. Column and row rounds
    alternate, so the standard Salsa20 permutation uses 20 rounds.

    The input and output are sixteen words packed from word 0 (most
    significant) through word 15 (least significant), matching the retained
    CLAASP vectors.

    Examples:
        >>> from claasp_next.primitives.permutations.salsa import Salsa
        >>> state = 1 << (15 * 32)
        >>> hex(Salsa(number_of_rounds=2).evaluate(state))
        '0x8186a22d0040a2848247921006929051080000900240220000004000008000000001020020400000080081040000000020500000a00000400008180a612a8020'
    """

    def __init__(
        self,
        number_of_rounds: int = 20,
        *,
        word_size: int = 32,
        rotations: tuple[int, int, int, int] = (7, 9, 13, 18),
    ) -> None:
        if not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        if not isinstance(word_size, int) or isinstance(word_size, bool) or word_size <= 0:
            raise ValueError("word_size must be a positive integer")
        if len(rotations) != 4 or any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < word_size
            for value in rotations
        ):
            raise ValueError("rotations must contain four integers in range(word_size)")

        super().__init__("salsa", {"state": ValueType(Word(word_size), (16,))})
        state: list[Port | Selection] = [self.input("state")[index] for index in range(16)]
        for round_number in range(number_of_rounds):
            self.add_round()
            groups = _COLUMNS if round_number % 2 == 0 else _ROWS
            for quarter_number, (a, b, c, d) in enumerate(groups):
                state[a], state[b], state[c], state[d] = self._quarter_round(
                    state[a], state[b], state[c], state[d], rotations,
                    f"round_{round_number}_quarter_{quarter_number}",
                )
        self.set_output(self.add_component(Concatenate(state, component_id="permutation_output")))

    def _quarter_round(
        self,
        a: Port | Selection,
        b: Port | Selection,
        c: Port | Selection,
        d: Port | Selection,
        rotations: tuple[int, int, int, int],
        prefix: str,
    ) -> tuple[Port | Selection, Port, Port, Port]:
        b = self._add_rotate_xor(a, d, b, rotations[0], f"{prefix}_step_0")
        c = self._add_rotate_xor(a, b, c, rotations[1], f"{prefix}_step_1")
        d = self._add_rotate_xor(b, c, d, rotations[2], f"{prefix}_step_2")
        a = self._add_rotate_xor(c, d, a, rotations[3], f"{prefix}_step_3")
        return a, b, c, d

    def _add_rotate_xor(
        self,
        left: Port | Selection,
        right: Port | Selection,
        destination: Port | Selection,
        rotation: int,
        prefix: str,
    ) -> Port:
        added = self.add_component(ModularAdd((left, right), component_id=f"{prefix}_add"))
        rotated = self.add_component(Rotate(added, rotation, "left", component_id=f"{prefix}_rotate"))
        return self.add_component(Xor((destination, rotated), component_id=f"{prefix}_xor"))
