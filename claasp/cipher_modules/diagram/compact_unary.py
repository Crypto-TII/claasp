"""Compact compatible independent vertical unary rows without rerouting bits."""


def _unary_row(cells):
    boxes = [(column, cell) for column, cell in cells.items() if cell['kind'] == 'box']
    if len(boxes) != 1:
        return None
    column, cell = boxes[0]
    definition = cell['definition']
    if (
        definition['type'] != 'word_operation'
        or definition['description'][0] not in ('ROTATE', 'SHIFT', 'NOT')
        or cell['ports'] != {'top': 'in', 'bottom': 'out'}
    ):
        return None
    for other_column, other in cells.items():
        if other_column != column and (other['kind'] != 'wire' or other['ports'] != {'top': 'in', 'bottom': 'out'}):
            return None
    return column, (definition['round'], definition['bits'], tuple(definition['description']))


def _can_extend(group, candidate, maximum):
    """Check the semantic signature, distinct destination and cohort bound."""
    return (
        candidate is not None
        and group['signature'] == candidate[1]
        and candidate[0] not in group['columns']
        and len(group['rows']) < maximum
    )


def _row_groups(rows, row_count, maximum):
    """Partition consecutive rows without crossing a non-unary boundary."""
    groups = []
    for row in range(row_count):
        candidate = _unary_row(rows.get(row, {}))
        if groups and _can_extend(groups[-1], candidate, maximum):
            groups[-1]['rows'].append(row)
            groups[-1]['columns'].add(candidate[0])
        else:
            groups.append(
                {
                    'rows': [row],
                    'columns': {candidate[0]} if candidate else set(),
                    'signature': candidate[1] if candidate else None,
                }
            )
    return groups


def compact(model, maximum):
    """Merge adjacent compatible unary rows on disjoint vertical streams.

    Actual vertical ports prove distinct lane dependencies: no horizontal route
    or repeated destination is merged. Native operation descriptions/rounds must
    agree. Constants, interfaces and other operations are never merged. Record
    coordinates follow the actual new cells; no dependency metadata repairs a wire.
    """
    if maximum == 1:
        return model
    rows = {}
    for (row, column), cell in model['cells'].items():
        rows.setdefault(row, {})[column] = cell
    groups = _row_groups(rows, model['rows'], maximum)
    mapping = {old: new for new, group in enumerate(groups) for old in group['rows']}
    cells = {}
    for (row, column), cell in sorted(model['cells'].items()):
        key = (mapping[row], column)
        # A box replaces the carried vertical wire at its own independent lane.
        if key not in cells or cell['kind'] == 'box':
            cells[key] = cell
    for record in model['records']:
        record['row'] = mapping[record['row']]
    model.update(cells=cells, rows=len(groups))
    return model
