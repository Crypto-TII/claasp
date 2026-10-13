"""Vector rendering of the validated persistent word cells and actual routes."""
import json
import re
from math import isfinite
from . import word_visual, word_bindings, manual_blocks
from .presentation import escape


def _label(cell, style):
    definition = cell['definition']
    if definition['type'] == 'constant':
        return 'x'+format(int(definition['description'][0], 0), '02X')
    return manual_blocks.label(definition, style)


def _point(column, row, dx=0, dy=0):
    return f'({column+dx:.4f},{-row+dy:.4f})'


def render_model(model, *, operator_style='symbols', wire_borders=False,
                 columnSpacing=1.4, rowSpacing=1.0, boxWidth=.98, boxHeight=.65,
                 anchorPrefix='word', rowsPerPanel=24, columnsPerPanel=16,
                 maxPanels=256, pageBreaks=False):
    r"""
    Render the exact word-view cells without choosing another placement.

    INPUT:

    - ``model`` -- **dictionary**; validated ``word_visual.build`` model
    - ``operator_style`` -- **string**; ``'symbols'`` or ``'labels'``
    - ``wire_borders`` -- **boolean**; optional outlines around wiring cells
    - spacing/box dimensions are positive **numbers** in centimetres
    - panel controls crop the same global grid, with explicit continuation labels

    OUTPUT:

    A TikZ **string** with globally stable coordinate names. No operation,
    observer or interface helper boxes are introduced by the vector renderer.
    """
    if operator_style not in ('symbols', 'labels') or type(wire_borders) is not bool:
        raise ValueError('Invalid persistent TikZ label/border option')
    dimensions = (columnSpacing, rowSpacing, boxWidth, boxHeight)
    if any(type(value) not in (int, float) or not isfinite(value) or value <= 0 for value in dimensions):
        raise ValueError('Persistent TikZ dimensions must be finite positive numbers')
    if boxWidth >= columnSpacing or boxHeight >= rowSpacing:
        raise ValueError('Box dimensions must leave positive route gaps')
    if not isinstance(anchorPrefix, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*', anchorPrefix):
        raise ValueError('Invalid persistent TikZ anchor prefix')
    if any(type(value) is not int or value < 1 for value in (rowsPerPanel, columnsPerPanel, maxPanels)):
        raise ValueError('Persistent TikZ panel bounds must be positive integers')
    if type(pageBreaks) is not bool:
        raise ValueError('pageBreaks must be a boolean')
    panels = [(r, c) for r in range(0, model['rows'], rowsPerPanel)
              for c in range(0, model['columns'], columnsPerPanel)]
    if len(panels) > maxPanels:
        raise ValueError('Persistent TikZ exceeds maxPanels')
    sides = {'top': (0, .5), 'bottom': (0, -.5), 'left': (-.5, 0), 'right': (.5, 0)}
    anchors = {'top': 'north', 'bottom': 'south', 'left': 'west', 'right': 'east'}
    output = []
    for panel_index, (first_row, first_column) in enumerate(panels):
        if panel_index:
            output.append(r'\clearpage' if pageBreaks else r'\par\bigskip')
        output += [f'% word-view panel {panel_index}: rows {first_row}:{min(first_row+rowsPerPanel,model["rows"])} columns {first_column}:{min(first_column+columnsPerPanel,model["columns"])}',
                   rf'\begin{{tikzpicture}}[x={columnSpacing}cm,y={rowSpacing}cm,>=stealth,font=\small\ttfamily,line width=.4pt]']
        for (row, column), cell in sorted(model['cells'].items()):
            if not first_row <= row < first_row+rowsPerPanel or not first_column <= column < first_column+columnsPerPanel:
                continue
            x, y = column-first_column, row-first_row
            center = _point(x, y)
            name = f'{anchorPrefix}-W{row}x{column}'
            ports = cell['ports']
            if cell['kind'] in ('box', 'input', 'output'):
                height = boxHeight if cell['kind'] == 'box' else .25
                label = _label(cell, operator_style) if cell['kind'] == 'box' else ''
                label = escape(label).replace('>', r'\textgreater{}').replace('<', r'\textless{}')
                output.append(rf'\node[draw,minimum width={boxWidth}cm,minimum height={height}cm,inner sep=.5mm,outer sep=0pt] ({name}) at {center} {{{label}}};')
                if cell.get('secret'):
                    output.append(rf'\node[anchor=east,inner sep=.3mm] at ({name}.west) {{S}};')
                for side, direction in ports.items():
                    dx, dy = sides[side]
                    boundary = _point(x, y, dx, dy)
                    node = f'({name}.{anchors[side]})'
                    output.append(rf'\draw[->] {boundary} -- {node};' if direction == 'in' else rf'\draw {node} -- {boundary};')
                if cell['kind'] == 'box':
                    record = {'row': row, 'column': column, 'definition': cell['definition']}
                    output.append('% word-native '+json.dumps(record, sort_keys=True, separators=(',', ':')))
            else:
                if wire_borders:
                    output.append(rf'\draw[gray!40,line width=.2pt] {_point(x,y,-.35,-.35)} rectangle {_point(x,y,.35,.35)};')
                if cell['kind'] == 'cross':
                    output.append(rf'\draw {_point(x,y,-.5,0)} -- {_point(x,y,.5,0)};')
                    output.append(rf'\draw[preaction={{draw=white,line width=2.2pt}}] {_point(x,y,0,.5)} -- {_point(x,y,0,-.5)};')
                else:
                    for side in ports:
                        dx, dy = sides[side]
                        output.append(rf'\draw {center} -- {_point(x,y,dx,dy)};')
                    if cell['kind'] == 'fork':
                        output.append(rf'\fill {center} circle[radius=.55mm];')
            # A cropped route is labelled as a continuation, never as a fake IO.
            for side in ports:
                crosses = (side == 'top' and row == first_row and row > 0
                           or side == 'bottom' and row == first_row+rowsPerPanel-1 and row < model['rows']-1
                           or side == 'left' and column == first_column and column > 0
                           or side == 'right' and column == first_column+columnsPerPanel-1 and column < model['columns']-1)
                if crosses:
                    dx, dy = sides[side]
                    reference = f'V{row if side == "top" else row+1}:{column}' if side in ('top', 'bottom') else f'H{row}:{column if side == "left" else column+1}'
                    output.append(rf'\node[font=\tiny\ttfamily,fill=white,inner sep=.2mm] at {_point(x,y,dx,dy)} {{{escape(reference)}}};')
        output.append(r'\end{tikzpicture}')
    return '\n'.join(output)+'\n'


def to_tikz(ir, **options):
    r"""
    Reparse the ordinary word picture, then render its exact placement as TikZ.

    INPUT:

    - ``ir`` -- **dictionary**; admitted persistent word graph
    - ``options`` -- ``key_side``, ``word_bits``, work bounds and ``render_model`` controls

    OUTPUT:

    A TikZ **string**. The native bindings and ordinary ASCII body are unchanged.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher, to_tikz
        sage: text = to_tikz(from_cipher(SpeckBlockCipher(number_of_rounds=int(1))), layoutSource='persistent')
        sage: text.count('% word-native ')
        5
    """
    maximum_text = options.pop('max_text_bytes', 64000000)
    if type(maximum_text) is not int or maximum_text < 1:
        raise ValueError('max_text_bytes must be a positive integer')
    keys = ('key_side', 'word_bits', 'max_calls', 'max_cells', 'max_grid_area')
    layout = {key: options.pop(key) for key in keys if key in options}
    body, bindings = word_bindings.export_bindings(ir, **layout)
    if word_bindings.decode_bindings(body, bindings) != ir:
        raise ValueError('Persistent vector source changed native bindings')
    model = word_visual.build(ir, **layout)
    if word_visual.render(model) != body:
        raise ValueError('Persistent vector placement differs from actual ASCII')
    text = render_model(model, **options)
    if len(text.encode('utf8')) > maximum_text:
        raise ValueError('Persistent TikZ exceeds max_text_bytes')
    return text
