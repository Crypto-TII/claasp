"""Reusable add-rotate-XOR composites."""

from claasp.components import ModularAdd, Rotate, Xor
from claasp.domains import Word
from claasp.graph import CompositeBuilder, CompositeDefinition, ValueType


def ChaChaQuarterRound(
    *,
    word_size: int = 32,
    rotations: tuple[int, int, int, int] = (16, 12, 8, 7),
) -> CompositeDefinition:
    """Return the four-word ChaCha quarter-round composition.

    EXAMPLES::

        >>> from claasp.composites import ChaChaQuarterRound
        >>> hex(ChaChaQuarterRound().evaluate(
        ...     0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567))
        '0xea2a92f4cb1cf8ce4581472e5881c4bb'
    """

    if not isinstance(word_size, int) or isinstance(word_size, bool) or word_size <= 0:
        raise ValueError("word_size must be a positive integer")
    if len(rotations) != 4 or any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < word_size
        for value in rotations
    ):
        raise ValueError("rotations must contain four integers in range(word_size)")

    value_type = ValueType(Word(word_size), (1,))
    builder = CompositeBuilder(
        "ChaChaQuarterRound", {name: value_type for name in ("a", "b", "c", "d")}
    )
    builder.add_round()
    a, b, c, d = (builder.input(name) for name in ("a", "b", "c", "d"))

    def xor_rotate(left, right, rotation, prefix):
        mixed = builder.add_component(Xor((left, right), component_id=f"{prefix}_xor"))
        return builder.add_component(
            Rotate(mixed, rotation, "left", component_id=f"{prefix}_rotate")
        )

    a = builder.add_component(ModularAdd((a, b), component_id="add_0"))
    d = xor_rotate(d, a, rotations[0], "xor_rotate_0")
    c = builder.add_component(ModularAdd((c, d), component_id="add_1"))
    b = xor_rotate(b, c, rotations[1], "xor_rotate_1")
    a = builder.add_component(ModularAdd((a, b), component_id="add_2"))
    d = xor_rotate(d, a, rotations[2], "xor_rotate_2")
    c = builder.add_component(ModularAdd((c, d), component_id="add_3"))
    b = xor_rotate(b, c, rotations[3], "xor_rotate_3")

    for name, output in (("a", a), ("b", b), ("c", c), ("d", d)):
        builder.set_output(name, output)
    joined = builder.join(a, b, c, d)
    builder.set_output("output", joined)
    return builder.build(provenance={"specification": "RFC 8439 section 2.1"})
