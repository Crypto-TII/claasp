"""Shared compact formatting for graph selections and annotation payloads."""

from claasp_next.semantics.cryptanalysis import BitPattern, Transition


def format_positions(positions: tuple[int, ...]) -> str:
    """Compact consecutive selections while preserving arbitrary permutations."""

    if positions == tuple(range(positions[0], positions[0] + len(positions))):
        return str(positions[0]) if len(positions) == 1 else f"{positions[0]}:{positions[-1] + 1}"
    return ",".join(str(position) for position in positions)


def format_annotation(value: object | None) -> str | None:
    """Return a short human-readable annotation label."""

    if value is None:
        return None
    if isinstance(value, Transition):
        source = value.input_pattern.value
        output = value.output_pattern.value
        return f"0x{source:x}->0x{output:x} w={value.weight:g}"
    if isinstance(value, BitPattern):
        return f"0x{value.value:x}"
    if isinstance(value, tuple):
        if len(value) <= 4:
            return (
                "("
                + ",".join(f"0x{item:x}" if isinstance(item, int) else str(item) for item in value)
                + ")"
            )
        return f"{len(value)} units"
    return str(value)
