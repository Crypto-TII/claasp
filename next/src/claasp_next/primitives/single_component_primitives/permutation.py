"""One-component logical-unit permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Bit, Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Permutation(Primitive):
    """Apply ``output[i] = input[mapping[i]]`` to bits or words."""

    def __init__(self, mapping=None, word_size: int = 1) -> None:
        word_size = positive(word_size, "word_size")
        mapping = list(reversed(range(8))) if mapping is None else list(mapping)
        count = len(mapping)
        domain = Bit() if word_size == 1 else Word(word_size)
        super().__init__(
            "permutation", {"input": ValueType(domain, (count,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(PermutationComponent(
            self.input("input"), mapping,
        )))


__all__ = ["Permutation"]
