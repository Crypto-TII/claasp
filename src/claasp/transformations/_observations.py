"""Preserve retained inspectable boundaries through immutable graph rewrites."""

from itertools import groupby
from typing import Any

from claasp.graph import as_selection
from claasp.unit_types import BinaryExtensionField, Bit, Word


def _encoded_view(derived, refs, array_type):
    pieces = []
    for source_id, group in groupby(refs, key=lambda item: item[0]):
        source = derived.graph.unit_array(source_id)
        bits = (
            source
            if isinstance(source.array_type.unit_type, Bit)
            else derived._builder.unpack_bits(source)
        )
        pieces.append(bits[tuple(bit for _, bit in group)])
    joined = derived._builder.join(*pieces)
    unit = array_type.unit_type
    if isinstance(unit, Bit):
        return as_selection(joined)
    return as_selection(
        derived._builder.pack_bits(
            joined,
            unit.encoded_bit_size,
            output_unit_type=unit if isinstance(unit, BinaryExtensionField) else None,
        )
    )


def _preserve_observations(source, derived, arrays, rounds, *, replacements=None, outputs=None):
    """Remap retained observations; omitted slice regions have no observation."""
    replacements = {} if replacements is None else replacements
    resolved = {}
    cache: dict[tuple[str, tuple[int, ...]], Any] = {}

    def remap(value):
        selection = as_selection(value)
        key = selection.source.source_id, selection.positions
        if key in cache:
            return cache[key]
        unit = selection.array_type.unit_type
        if not isinstance(unit, (Bit, Word, BinaryExtensionField)):
            result = as_selection(arrays[selection.source.source_id])[selection.positions]
        else:
            target = []
            for name, bit in source.graph.selection_bit_sources(as_selection(selection)):
                if (name, bit) in replacements:
                    target.append(replacements[name, bit])
                else:
                    if name not in resolved:
                        resolved[name] = derived.graph.selection_bit_sources(
                            as_selection(arrays[name])
                        )
                    target.append(resolved[name][bit])
            result = _encoded_view(derived, tuple(target), selection.array_type)
        cache[key] = result
        return result

    published: dict[int, dict[str, Any]] = {}
    source_published = getattr(source, "_published_intermediate_outputs", {})
    for number, observations in source_published.items():
        if number not in rounds:
            continue
        target_number = rounds[number].number
        for name, value in observations.items():
            try:
                selections = value if isinstance(value, tuple) else (value,)
                if name == "round_output" and replacements:
                    refs = tuple(
                        ref
                        for selection in selections
                        for ref in source.graph.selection_bit_sources(as_selection(selection))
                    )
                    if refs and all(ref in replacements for ref in refs):
                        continue
                mapped = tuple(remap(selection) for selection in selections)
            except (KeyError, IndexError):
                continue
            published.setdefault(target_number, {})[name] = (
                mapped[0] if len(mapped) == 1 else mapped
            )
    if published:
        derived._published_intermediate_outputs = published
    keys: list[Any] = []
    for value in getattr(source, "_published_round_keys", ()):
        try:
            if isinstance(value, dict):
                keys.append({name: remap(item) for name, item in value.items()})
            elif isinstance(value, tuple):
                keys.append(tuple(remap(item) for item in value))
            else:
                keys.append(remap(value))
        except (KeyError, IndexError):
            continue
    if keys:
        derived._published_round_keys = tuple(keys)
    if outputs is None:
        outputs = (source.graph.output,)
    try:
        selected = tuple(
            ref for output in outputs for ref in source.graph.selection_bit_sources(output)
        )
        ends_at_round = any(
            selected
            == tuple(
                ref
                for selection in selections
                for ref in source.graph.selection_bit_sources(as_selection(selection))
            )
            for _, selections in source.graph.round_output_boundaries
        )
    except TypeError:
        ends_at_round = False
    if ends_at_round:
        count = sum("round_output" in values for values in published.values())
        if count:
            derived._round_count = count


def _boundary_bit_replacements(source, derived, boundaries):
    result: dict[tuple[str, int], tuple[str, int]] = {}
    ambiguous = set()
    for source_id, (name, positions, offset) in boundaries.items():
        original = source.graph.unit_array(source_id)[positions]
        target = derived.graph.input(name)[tuple(range(offset, offset + len(positions)))]
        try:
            old_refs = source.graph.selection_bit_sources(original)
            new_refs = derived.graph.selection_bit_sources(target)
        except TypeError:
            continue
        for old, new in zip(old_refs, new_refs):
            if old in result and result[old] != new:
                ambiguous.add(old)
            else:
                result[old] = new
    return {key: value for key, value in result.items() if key not in ambiguous}
