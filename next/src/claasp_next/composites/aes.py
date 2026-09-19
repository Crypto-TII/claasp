"""Reusable blocks used to compose AES and AES-derived study variants."""

from collections.abc import Iterable

from claasp_next.components import Add, BinaryAffineMap, Constant, LinearMap, Permutation, Power
from claasp_next.composites.substitution import ParallelSBoxLayer
from claasp_next.domains import BinaryExtensionField
from claasp_next.graph import CompositeBuilder, CompositeDefinition, ValueType, as_selection
from claasp_next.utils import binary_field_power, repeat_block_diagonal, rotate_left


AES_FIELD = BinaryExtensionField(8, 0x11B)
AES_SBOX = tuple(
    inverse ^ rotate_left(inverse, 1, 8) ^ rotate_left(inverse, 2, 8)
    ^ rotate_left(inverse, 3, 8) ^ rotate_left(inverse, 4, 8) ^ 0x63
    for inverse in (binary_field_power(AES_FIELD, value, 254) if value else 0 for value in range(256))
)


def _aes_affine_linear(value: int) -> int:
    return (
        value ^ rotate_left(value, 1, 8) ^ rotate_left(value, 2, 8)
        ^ rotate_left(value, 3, 8) ^ rotate_left(value, 4, 8)
    )


AES_AFFINE_MATRIX = tuple(
    tuple(
        (_aes_affine_linear(1 << (7 - column)) >> (7 - row)) & 1
        for column in range(8)
    )
    for row in range(8)
)
MIX_COLUMNS_MATRIX = repeat_block_diagonal(
    ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)), 4
)
SHIFT_ROWS_MAPPING = tuple(4 * ((column + row) % 4) + row for column in range(4) for row in range(4))
ROUND_CONSTANTS = (1, 2, 4, 8, 16, 32, 64, 128, 27, 54)


def AESSubstitutionLayer(
    unit_count: int,
    *,
    table: Iterable[int] = AES_SBOX,
    realization: str = "lookup",
) -> CompositeDefinition:
    """Return an AES-byte substitution layer over ``unit_count`` bytes.

    EXAMPLES::

        >>> from claasp_next.composites import AESSubstitutionLayer
        >>> hex(AESSubstitutionLayer(1).evaluate(0x53))
        '0xed'
    """

    if not isinstance(unit_count, int) or isinstance(unit_count, bool) or unit_count <= 0:
        raise ValueError("unit_count must be a positive integer")
    if realization == "lookup":
        return ParallelSBoxLayer(tuple(table), unit_count, domain=AES_FIELD)
    if realization != "algebraic":
        raise ValueError("AES substitution realization must be 'lookup' or 'algebraic'")
    if tuple(table) != AES_SBOX:
        raise ValueError("the algebraic realization is defined only for the canonical AES S-box")

    builder = CompositeBuilder("AESSubstitutionLayer", {"state": ValueType(AES_FIELD, (unit_count,))})
    builder.add_round()
    inverse = builder.add_component(Power(builder.input("state"), 254, component_id="inverse"))
    output = builder.add_component(
        BinaryAffineMap(inverse, AES_AFFINE_MATRIX, 0x63, component_id="affine")
    )
    builder.set_output("output", output)
    return builder.build(provenance={"specification": "FIPS 197 SubBytes"})


def AESKeySchedule(
    key_bit_size: int = 128,
    number_of_rounds: int | None = None,
    *,
    sbox_table: Iterable[int] = AES_SBOX,
    realization: str = "lookup",
) -> CompositeDefinition:
    """Return the AES key-expansion block with named round-key outputs.

    EXAMPLES::

        >>> from claasp_next.composites import AESKeySchedule
        >>> schedule = AESKeySchedule(128, 1)
        >>> hex(schedule.evaluate(0x000102030405060708090A0B0C0D0E0F,
        ...     output="round_key_1"))
        '0xd6aa74fdd2af72fadaa678f1d6ab76fe'
    """

    if key_bit_size not in (128, 192, 256):
        raise ValueError("AES key_bit_size must be 128, 192, or 256")
    standard_rounds = {128: 10, 192: 12, 256: 14}[key_bit_size]
    rounds = standard_rounds if number_of_rounds is None else number_of_rounds
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= standard_rounds:
        raise ValueError(f"AES-{key_bit_size} requires between 1 and {standard_rounds} rounds")
    table = tuple(sbox_table)
    word_count = key_bit_size // 32
    word_type = ValueType(AES_FIELD, (4,))
    builder = CompositeBuilder("AESKeySchedule", {"key": ValueType(AES_FIELD, (key_bit_size // 8,))})
    builder.add_round()
    words = [builder.input("key")[4 * index : 4 * index + 4] for index in range(word_count)]
    while len(words) < 4 * (rounds + 1):
        word_index = len(words)
        temporary = as_selection(words[-1])
        if word_index % word_count == 0:
            expansion_index = word_index // word_count
            rotated = temporary.source.select(
                temporary.positions[1], temporary.positions[2], temporary.positions[3], temporary.positions[0]
            )
            substitution = builder.add_composite(
                AESSubstitutionLayer(4, table=table, realization=realization),
                {"state": rotated}, scope_id=f"sub_word_{expansion_index}",
            )
            constant = builder.add_component(Constant(
                word_type, (ROUND_CONSTANTS[expansion_index - 1], 0, 0, 0),
                component_id=f"round_constant_{expansion_index}",
            ))
            temporary = builder.add_component(Add(
                (substitution.output(), constant), component_id=f"add_constant_{expansion_index}"
            ))
        elif word_count == 8 and word_index % word_count == 4:
            substitution = builder.add_composite(
                AESSubstitutionLayer(4, table=table, realization=realization),
                {"state": temporary}, scope_id=f"sub_word_{word_index}",
            )
            temporary = substitution.output()
        word = builder.add_component(Add(
            (as_selection(words[word_index - word_count]), temporary), component_id=f"word_{word_index}"
        ))
        words.append(word)

    round_keys = []
    for round_number in range(rounds + 1):
        selected = words[4 * round_number : 4 * round_number + 4]
        round_key = builder.input("key")[:16] if round_number == 0 else builder.join(*selected)
        builder.set_output(f"round_key_{round_number}", round_key)
        round_keys.append(round_key)
    expanded = builder.join(*round_keys)
    builder.set_output("output", expanded)
    return builder.build(provenance={"specification": "FIPS 197 key expansion"})


def AESRound(
    *,
    sbox_table: Iterable[int] = AES_SBOX,
    mix_columns: bool = True,
    realization: str = "lookup",
) -> CompositeDefinition:
    """Return one AES encryption round with named intermediate boundaries.

    EXAMPLES::

        >>> from claasp_next.composites import AESRound
        >>> hex(AESRound().evaluate(0x00102030405060708090A0B0C0D0E0F0,
        ...     0xD6AA74FDD2AF72FADAA678F1D6AB76FE))
        '0x89d810e8855ace682d1843d8cb128fe4'
    """

    if not isinstance(mix_columns, bool):
        raise TypeError("mix_columns must be a bool")
    state_type = ValueType(AES_FIELD, (16,))
    builder = CompositeBuilder("AESRound", {"state": state_type, "round_key": state_type})
    builder.add_round()
    substitution = builder.add_composite(
        AESSubstitutionLayer(16, table=tuple(sbox_table), realization=realization),
        {"state": builder.input("state")}, scope_id="sub_bytes",
    )
    builder.set_output("sub_bytes", substitution.output())
    state = builder.add_component(
        Permutation(substitution.output(), SHIFT_ROWS_MAPPING, component_id="shift_rows")
    )
    builder.set_output("shift_rows", state)
    if mix_columns:
        state = builder.add_component(LinearMap(state, MIX_COLUMNS_MATRIX, component_id="mix_columns"))
        builder.set_output("mix_columns", state)
    state = builder.add_component(Add((state, builder.input("round_key")), component_id="add_round_key"))
    builder.set_output("output", state)
    return builder.build(provenance={"specification": "FIPS 197 encryption round"})
