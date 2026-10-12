"""Generic observation states, dependency frontiers and paginated state cells."""
from claasp.diagram_validation import validate


def _state_options(mode, order, word_bits, columns):
    if mode not in {'declared', 'layer', 'round'} or order not in {'source', 'reverse'}:
        raise ValueError('Unknown state snapshot mode or order')
    valid_word = type(word_bits) is int and word_bits > 0
    valid_columns = columns is None or (type(columns) is int and columns > 0)
    if not valid_word or not valid_columns:
        raise ValueError('Positive explicit word width/columns required')


def _declared_groups(ir):
    return [(node['id'], node['round'], [(edge['source'], bit) for edge in node['operands'] for bit in edge['positions']])
            for node in ir['nodes'] if node['type'] in {'intermediate_output', 'cipher_output'}]


def _ranks(ir, mode):
    if mode == 'layer':
        from claasp.diagrams import layout
        positions = layout(ir)
        ranks = {item['id']: 0 for item in ir['inputs']}
        ranks.update({node['id']: positions[node['id']]['layer'] for node in ir['nodes']})
        return ranks
    ranks = {item['id']: -1 for item in ir['inputs']}
    ranks.update({node['id']: node['round'] for node in ir['nodes']})
    return ranks


def _consumers(ir, ranks):
    consumers = {identity: [] for identity in ranks}
    for node in ir['nodes']:
        for edge in node['operands']:
            consumers[edge['source']].append(ranks[node['id']])
    return consumers


def _live_at(node, cut, ranks, consumers, final):
    if ranks[node['id']] > cut:
        return False
    return any(rank > cut for rank in consumers[node['id']]) or node['id'] == final


def _frontier_groups(ir, mode):
    ranks = _ranks(ir, mode)
    consumers = _consumers(ir, ranks)
    final = next(node['id'] for node in ir['nodes'] if node['type'] == 'cipher_output')
    groups = []
    for cut in sorted(set(ranks.values())):
        live = [node for node in ir['inputs']+ir['nodes'] if _live_at(node, cut, ranks, consumers, final)]
        positions = [(node['id'], bit) for node in live for bit in range(node['bits'])]
        groups.append((f'{mode}-{cut}', cut, positions))
    return groups


def _value_bit(source, bit, widths, values, kind):
    if source not in values or type(values[source]) is not int or not 0 <= values[source] < 2**widths[source]:
        raise ValueError(f'Missing or out-of-range {kind} value')
    return (values[source] >> (widths[source]-1-bit)) & 1


def _word_value(positions, widths, values, kind='component'):
    value = 0
    for source, bit in positions:
        value = (value << 1) | _value_bit(source, bit, widths, values, kind)
    return value


def _word(positions, widths, values, comparison):
    value = None
    difference = None
    active = None
    if values is not None:
        value = _word_value(positions, widths, values)
        active = bool(value)
        if comparison is not None:
            difference = value ^ _word_value(positions, widths, comparison, kind='comparison')
            active = bool(difference)
    return {'positions': positions, 'value': value, 'difference': difference, 'active': active}


def _snapshot(identity, stage, positions, widths, mode, order, word_bits, columns, values, comparison):
    if order == 'reverse':
        positions = list(reversed(positions))
    if len(positions) % word_bits:
        raise ValueError('Explicit word width must divide selected state bits')
    words = [_word(positions[start:start+word_bits], widths, values, comparison)
             for start in range(0, len(positions), word_bits)]
    cols = columns or max(1, len(words))
    geometry = 'explicit-columns' if columns else 'ambiguous-flat-fallback'
    return {'id': identity, 'stage': stage, 'mode': mode, 'order': order,
            'word_bits': word_bits, 'columns': cols, 'rows': (len(words)+cols-1)//cols,
            'geometry': geometry, 'words': words}


def snapshots(ir, *, mode='declared', word_bits=1, columns=None, order='source', values=None, comparison=None):
    validate(ir)
    _state_options(mode, order, word_bits, columns)
    widths = {node['id']: node['bits'] for node in ir['inputs']+ir['nodes']}
    groups = _declared_groups(ir) if mode == 'declared' else _frontier_groups(ir, mode)
    return [_snapshot(identity, stage, positions, widths, mode, order, word_bits, columns, values, comparison)
            for identity, stage, positions in groups]


def _display_value(word):
    if word['difference'] is not None:
        return word['difference']
    return word['value']


def _ascii_cell(word, digits, size):
    value = _display_value(word)
    text = '?' if value is None else f'{value:0{digits}x}'
    text += '*' if word['active'] else ' '
    return text.center(size)


def _ascii_row(frame, row, digits, size):
    cells = []
    for col in range(frame['columns']):
        index = row*frame['columns']+col
        if index >= len(frame['words']):
            cells.append(' '*size)
        else:
            cells.append(_ascii_cell(frame['words'][index], digits, size))
    return '|'+ '|'.join(cells)+'|'


def _ascii_frame(frame):
    lines = [f"{frame['id']} ({frame['mode']}, {frame['geometry']}, order={frame['order']}, word_bits={frame['word_bits']})"]
    digits = (frame['word_bits']+3)//4
    size = max(5, digits+3)
    border = '+'+'+'.join('-'*size for _ in range(frame['columns']))+'+'
    for row in range(frame['rows']):
        lines.extend([border, _ascii_row(frame, row, digits, size)])
    lines.extend([border, ''])
    return lines


def ascii_states(ir, **options):
    return '\n'.join(line for frame in snapshots(ir, **options) for line in _ascii_frame(frame))


def _tex_escape(text):
    replacements = {'_': r'\_', '%': r'\%', '&': r'\&', '#': r'\#', '{': r'\{', '}': r'\}',
                    '\\': r'\textbackslash{}', '$': r'\$', '^': r'\textasciicircum{}', '~': r'\textasciitilde{}'}
    return ''.join(replacements.get(char, char) for char in str(text))


def _tex_wrapped(text):
    return ''.join(_tex_escape(char)+(r'\allowbreak{}' if (index+1) % 12 == 0 else '')
                   for index, char in enumerate(str(text)))


def _pagination(cell_width, cell_height, rows, columns, maximum, page_breaks):
    if cell_width <= 0 or cell_height <= 0:
        raise ValueError('Positive cell spacing required')
    if any(type(value) is not int or value <= 0 for value in (rows, columns, maximum)) or type(page_breaks) is not bool:
        raise ValueError('Invalid state pagination options')


def _selected_frames(frames, frame_range):
    if frame_range is None:
        return frames
    valid_pair = isinstance(frame_range, (list, tuple)) and len(frame_range) == 2
    if not valid_pair or any(type(value) is not int for value in frame_range):
        raise ValueError('Invalid state frame range')
    if not 0 <= frame_range[0] < frame_range[1] <= len(frames):
        raise ValueError('Invalid state frame range')
    return frames[frame_range[0]:frame_range[1]]


def _state_tiles(frames, rows, columns):
    for frame in frames:
        for top in range(0, frame['rows'], rows):
            occupied_columns = min(frame['columns'], len(frame['words'])-top*frame['columns'])
            for left in range(0, occupied_columns, columns):
                yield frame, top, left


def _panel_count(frames, rows, columns):
    return sum(1 for _ in _state_tiles(frames, rows, columns))


def _panel_words(frame, top, bottom, left, right):
    for index, word in enumerate(frame['words']):
        row, col = divmod(index, frame['columns'])
        if top <= row < bottom and left <= col < right:
            yield index, word, row, col


def _word_nodes(frame, index, word, row, col, top, left, cell_width, cell_height, row_gap, legend):
    value = _display_value(word)
    text = '?' if value is None else f"{value:0{(frame['word_bits']+3)//4}x}"
    if len(text) > 6:
        key = f'V{index}'
        legend.append((key, text))
        text = key
    fill = 'orange!25' if word['active'] else 'white'
    x, y = (col-left)*cell_width, -(row-top)*(cell_height+row_gap)
    return [fr"\node[draw,fill={fill},minimum width={cell_width}cm,minimum height={cell_height}cm] at ({x},{y}) {{{text}}};",
            fr"\node[font=\tiny,anchor=south] at ({x},{y+cell_height/2}) {{{index}}};"]


def _state_panel(frame, top, left, rows, columns, cell_width, cell_height, row_gap):
    bottom, right = min(frame['rows'], top+rows), min(frame['columns'], left+columns)
    title = f"{frame['id']}: {frame['geometry']}, {frame['word_bits']} bits/word, order {frame['order']}"
    lines = [r'\begin{tikzpicture}[font=\scriptsize]',
             fr"\node[anchor=south west,align=left,text width={columns*cell_width}cm] at (0,{cell_height/2+row_gap+.45}) {{{_tex_wrapped(title)}}};",
             fr"\node[anchor=west,font=\tiny] at (0,{cell_height/2+row_gap+.1}) {{original cell rows {top}--{bottom-1}, columns {left}--{right-1}; indices retained}};"]
    legend = []
    for index, word, row, col in _panel_words(frame, top, bottom, left, right):
        lines.extend(_word_nodes(frame, index, word, row, col, top, left, cell_width, cell_height, row_gap, legend))
    lines.append(r'\end{tikzpicture}\par\smallskip')
    for key, text in legend:
        lines.append(r'{\raggedright\scriptsize\noindent\textbf{'+key+'}: '+_tex_wrapped(text)+r'\par}\smallskip')
    return '\n'.join(lines)


def tikz_states(ir, *, cell_width=1, cell_height=.5, rows_per_panel=24, columns_per_panel=12,
                frame_range=None, page_breaks=True, max_panels=256, row_gap=.25, **options):
    _pagination(cell_width, cell_height, rows_per_panel, columns_per_panel, max_panels, page_breaks)
    if not isinstance(row_gap, (int, float)) or row_gap < .25:
        raise ValueError('State row_gap must leave at least .25 cm for index labels')
    frames = _selected_frames(snapshots(ir, **options), frame_range)
    count = _panel_count(frames, rows_per_panel, columns_per_panel)
    if count > max_panels:
        raise ValueError(f'State needs {count} panels; supply frame_range or larger max_panels')
    panels = [_state_panel(frame, top, left, rows_per_panel, columns_per_panel,
                           cell_width, cell_height, row_gap)
              for frame, top, left in _state_tiles(frames, rows_per_panel, columns_per_panel)]
    separator = r'\clearpage' if page_breaks else r'\par\medskip'
    return ('\n'+separator+'\n').join(panels)
