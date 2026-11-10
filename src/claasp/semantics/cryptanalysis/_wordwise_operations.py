"""Conservative elementary transfers for four-state XOR differences."""

from claasp.semantics.cryptanalysis.truncated import WordwiseDifferenceKind as Kind
from claasp.semantics.cryptanalysis.truncated import WordwiseXorDifference as Difference


def _modular(differences):
    """One changing operand remains nonzero by operand-wise bijectivity.

    Carries are not assumed to preserve a known XOR value. Multiple changing
    operands or unrestricted operands give an unrestricted output.
    """
    differences = tuple(differences)
    width = differences[0].width
    if width == 1:
        return Difference.xor_many(differences)
    active = tuple(item for item in differences if item.kind is not Kind.ZERO)
    kind = (
        Kind.ZERO
        if not active
        else Kind.NONZERO
        if len(active) == 1 and active[0].kind is not Kind.UNKNOWN
        else Kind.UNKNOWN
    )
    return Difference(width, kind)


def _boolean(differences):
    """AND/OR preserve equality, but activity alone does not prove activity."""
    differences = tuple(differences)
    if len(differences) == 1:
        return differences[0]
    return Difference(
        differences[0].width,
        Kind.ZERO if all(item.kind is Kind.ZERO for item in differences) else Kind.UNKNOWN,
    )


def _pack(bits, width):
    """Pack MSB-first abstract bits, retaining exact values where possible."""
    bits = tuple(bits)
    if len(bits) != width or any(item.width != 1 for item in bits):
        raise ValueError("wordwise packing requires one width-one difference per bit")
    value = sum(
        int(item.kind in (Kind.KNOWN, Kind.NONZERO)) << (width - 1 - i)
        for i, item in enumerate(bits)
    )
    if all(item.kind is not Kind.UNKNOWN for item in bits):
        return Difference.known(width, value) if value else Difference(width, Kind.ZERO)
    return Difference(width, Kind.NONZERO if value else Kind.UNKNOWN)


def _unpack(difference, width):
    """Unpack known values; abstract nonzero words lose joint bit correlation."""
    if difference.width != width:
        raise ValueError("wordwise unpack width must match its input")
    if difference.kind in (Kind.ZERO, Kind.KNOWN):
        value = difference.value or 0
        return tuple(
            Difference.known(1, 1) if value & (1 << (width - 1 - i)) else Difference(1, Kind.ZERO)
            for i in range(width)
        )
    return tuple(Difference(1, Kind.UNKNOWN) for _ in range(width))
