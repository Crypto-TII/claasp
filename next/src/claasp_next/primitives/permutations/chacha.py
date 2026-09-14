"""The fixed-length ChaCha permutation."""

from claasp_next.components import Concatenate, ModularAdd, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.graph import Primitive, Port, Selection, ValueType


_COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
_DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


class ChaCha(Primitive):
    """Build the word-oriented ChaCha permutation.

    ``number_of_rounds`` uses the standard ChaCha convention: one round
    applies four complete quarter rounds, alternating columns and diagonals.
    The standard permutation has 20 rounds.

    The input and output are sixteen words packed from word 0 (most
    significant) through word 15 (least significant), matching CLAASP's
    retained vectors.

    Examples:
        >>> from claasp_next.primitives.permutations.chacha import ChaCha
        >>> state = int("617078653320646e79622d326b206574"
        ...             "03020100070605040b0a09080f0e0d0c"
        ...             "13121110171615141b1a19181f1e1d1c"
        ...             "00000001090000004a00000000000000", 16)
        >>> hex(ChaCha().evaluate(state))
        '0x837778abe238d763a67ae21e5950bb2fc4f2d0c7fc62bb2f8fa018fc3f5ec7b7335271c2f29489f3eabda8fc82e46ebdd19c12b4b04e16de9e83d0cb4e3c50a2'
    """

    def __init__(
        self,
        number_of_rounds: int = 20,
        *,
        word_size: int = 32,
        rotations: tuple[int, int, int, int] = (16, 12, 8, 7),
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

        super().__init__("chacha", {"state": ValueType(Word(word_size), (16,))})
        state: list[Port | Selection] = [self.input("state")[index] for index in range(16)]
        for round_number in range(number_of_rounds):
            self.add_round()
            groups = _COLUMNS if round_number % 2 == 0 else _DIAGONALS
            for quarter_number, (a, b, c, d) in enumerate(groups):
                prefix = f"round_{round_number}_quarter_{quarter_number}"
                state[a], state[b], state[c], state[d] = self._quarter_round(
                    state[a], state[b], state[c], state[d], rotations, prefix
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
    ) -> tuple[Port, Port, Port, Port]:
        a = self.add_component(ModularAdd((a, b), component_id=f"{prefix}_add_0"))
        d = self._xor_rotate(d, a, rotations[0], f"{prefix}_xor_rotate_0")
        c = self.add_component(ModularAdd((c, d), component_id=f"{prefix}_add_1"))
        b = self._xor_rotate(b, c, rotations[1], f"{prefix}_xor_rotate_1")
        a = self.add_component(ModularAdd((a, b), component_id=f"{prefix}_add_2"))
        d = self._xor_rotate(d, a, rotations[2], f"{prefix}_xor_rotate_2")
        c = self.add_component(ModularAdd((c, d), component_id=f"{prefix}_add_3"))
        b = self._xor_rotate(b, c, rotations[3], f"{prefix}_xor_rotate_3")
        return a, b, c, d

    def _xor_rotate(
        self,
        left: Port | Selection,
        right: Port | Selection,
        rotation: int,
        prefix: str,
    ) -> Port:
        mixed = self.add_component(Xor((left, right), component_id=f"{prefix}_xor"))
        return self.add_component(Rotate(mixed, rotation, "left", component_id=f"{prefix}_rotate"))
