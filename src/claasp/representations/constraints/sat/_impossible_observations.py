"""Retain original boundary labels and decode directional round evidence."""


def _round_labels(original, sliced, *, start, stop):
    source_map = sliced.source_map
    targets = {}
    for number, pieces in sliced.primitive.graph.round_output_boundaries:
        refs = tuple(
            ref for piece in pieces for ref in sliced.primitive.graph.selection_bit_sources(piece)
        )
        targets[refs] = number
    labels: dict[int, tuple[int, ...]] = {}
    for number, pieces in original.graph.round_output_boundaries:
        if not start <= number < stop:
            continue
        try:
            refs = tuple(
                (source_map[name], bit)
                for piece in pieces
                for name, bit in original.graph.selection_bit_sources(piece)
            )
        except KeyError:
            continue
        if refs in targets:
            target = targets[refs]
            labels[target] = (*labels.get(target, ()), number + 1)
    return labels


def _decode_rounds(model, assignment, labels, *, inverse=False, wordwise=False):
    from claasp.representations.constraints.sat.trails import _truncated_pattern

    boundaries = (
        getattr(model.primitive, "_inverse_round_boundaries", ())
        if inverse
        else model.primitive.graph.round_output_boundaries
    )
    rows: list[tuple[int, object]] = []
    for number, pieces in boundaries:
        if number not in labels:
            continue
        if wordwise:
            from claasp.graph.propagation import resolve_selection
            from claasp.semantics.cryptanalysis._wordwise_operations import _pack, _unpack

            sources = {
                name: model._decode_words(words, assignment)
                for name, words in model._unit_arrays.items()
            }
            bindings = {item.binding_id: item for item in model.primitive.graph.bindings}
            cache: dict[str, tuple] = {}
            # Published observations may wrap a whole word in unpack/pack
            # bindings. Collapsing complete wire aliases preserves joint
            # nonzero information that bitwise unpacking would otherwise lose.
            values = []
            for piece in pieces:
                fallback = None
                width = piece.array_type.unit_type.encoded_bit_size
                refs = model.primitive.graph.selection_bit_sources(piece)
                for unit in range(piece.array_type.unit_count):
                    group = refs[unit * width : (unit + 1) * width]
                    names = {name for name, _ in group}
                    direct = None
                    if len(names) == 1:
                        source = next(iter(names))
                        original_width = model.primitive.graph.unit_array(
                            source
                        ).array_type.unit_type.encoded_bit_size
                        indices = tuple(bit for _, bit in group)
                        units = {bit // width for bit in indices}
                        if (
                            original_width == width
                            and len(units) == 1
                            and {bit % width for bit in indices} == set(range(width))
                        ):
                            direct = sources[source][next(iter(units))]
                            if direct.kind.value == 1:
                                from claasp.semantics.cryptanalysis import WordwiseXorDifference

                                value = sum(
                                    ((direct.value >> (width - 1 - bit % width)) & 1)
                                    << (width - 1 - i)
                                    for i, bit in enumerate(indices)
                                )
                                direct = WordwiseXorDifference.known(width, value)
                    if direct is None:
                        if fallback is None:
                            fallback = resolve_selection(
                                piece, sources, bindings, cache, pack=_pack, unpack=_unpack
                            )
                        direct = fallback[unit]
                    values.append(direct)
            pattern = tuple(values)

        else:
            bit_names = tuple(
                model._unit_arrays[name][bit]
                for piece in pieces
                for name, bit in model.primitive.graph.selection_bit_sources(piece)
            )
            pattern = _truncated_pattern(bit_names, assignment)
        rows.extend((label, pattern) for label in labels[number])
    return tuple(sorted(rows, key=lambda item: item[0]))
