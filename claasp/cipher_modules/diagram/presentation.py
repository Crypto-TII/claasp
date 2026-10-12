"""Readable, generic presentation of a wire-validated native computation."""
import json
import math
import re
from collections import Counter


def escape(value):
    substitutions = {'\\': r'\textbackslash{}', '_': r'\_', '%': r'\%', '&': r'\&',
                     '#': r'\#', '{': r'\{', '}': r'\}', '$': r'\$',
                     '^': r'\textasciicircum{}', '~': r'\textasciitilde{}'}
    return ''.join(substitutions.get(c, c) for c in str(value))


def wrapped(value, chunk=12):
    value = str(value)
    return r'\allowbreak{}'.join(escape(value[i:i + chunk]) for i in range(0, len(value), chunk))


def selections(positions):
    """Lossless ascending/descending stride runs; repeats stay explicit."""
    result = []
    index = 0
    while index < len(positions):
        end = index
        step = positions[index + 1] - positions[index] if index + 1 < len(positions) else 0
        if step:
            while end + 1 < len(positions) and positions[end + 1] - positions[end] == step:
                end += 1
        if end - index >= 2:
            result.append(f'{positions[index]}:{step}:{positions[end]}')
            index = end + 1
        else:
            result.append(str(positions[index]))
            index += 1
    return ','.join(result)


def _parameter_key(kind, description):
    return json.dumps([kind, description], separators=(',', ':'))


def _reference(kind, description, registry):
    if not registry:
        return None
    return registry.get(_parameter_key(kind, description))


def _word_label(node, short):
    description = node['description']
    name = description[0]
    label_name = name
    if short:
        label_name = {'ROTATE_BY_VARIABLE_AMOUNT': 'VROT',
                      'SHIFT_BY_VARIABLE_AMOUNT': 'VSHIFT', 'IDEA_MODMUL': 'MAPMUL'}.get(name, name)
    if name in ('NOT', 'REVERSE'):
        return f'{name}/{node["bits"]}(unary)'
    fixed_amount = name in ('ROTATE', 'SHIFT')
    parameters = 'arity='+str(description[1])
    if name in ('ROTATE_BY_VARIABLE_AMOUNT', 'SHIFT_BY_VARIABLE_AMOUNT'):
        parameters = ('dir=' if short else 'direction=')+str(description[1])
    elif fixed_amount or short:
        parameters = str(description[1])
    if len(description) > 2 and description[2] is not None:
        parameters += ',mod='+str(description[2])
    return f'{label_name}/{node["bits"]}({parameters})'


def _constant_label(node, registry):
    value = node['description'][0]
    if len(value) > 12:
        value = _reference('constant', node['description'], registry) or value
    return f'CONST/{node["bits"]}={value}'


def _output_label(node, registry, short):
    kind = node['type']
    name = 'OUT' if kind == 'cipher_output' else 'OBSERVE'
    label = name+'/'+str(node['bits'])
    reference = _reference(kind, node['description'], registry)
    if short:
        return label+(' '+reference if reference else '')
    return label+' tag='+(reference or node['description'][0])


def operation(node, registry=None, short=False):
    kind = node.get('type', node.get('kind', ''))
    if kind == 'word_operation':
        return _word_label(node, short)
    if kind == 'constant':
        return _constant_label(node, registry)
    if kind in ('cipher_output', 'intermediate_output'):
        return _output_label(node, registry, short)
    if kind in ('input', 'join', 'selection'):
        return {'input': 'INPUT', 'join': 'PACK', 'selection': 'SELECT'}[kind]+'/'+str(node['bits'])
    reference = _reference(kind, node.get('description', []), registry)
    return kind.upper()+'/'+str(node['bits'])+(' '+reference if reference else '')



def parameter_registry(ir):
    parameters = {}
    for node in ir['nodes']:
        if node['type'] not in ('word_operation', 'constant') or (node['type'] == 'constant' and len(node['description'][0]) > 12):
            key = json.dumps([node['type'], node['description']], separators=(',', ':'))
            if key not in parameters:
                parameters[key] = (f'P{len(parameters) + 1}', node['type'], node['description'])
    return parameters


class _Tex(str):
    """Generated TeX with plaintext available for bounded table wrapping.

    INPUT:

    - ``markup`` -- **string**; already generated/escaped TeX
    - ``plain_text`` -- **string** (default: ``None``); visible cell contents
    - ``prefix`` -- **string** (default: ``''``); zero-width generated anchor
    """
    def __new__(cls, markup, *, plain_text=None, prefix=''):
        value = super().__new__(cls, markup)
        value.plain_text = plain_text
        value.prefix = prefix
        return value


_TABLE_FONT_POINTS = 9
_TABLE_BASELINE_POINTS = 11
_TABLE_CHARACTER_POINTS = _TABLE_FONT_POINTS*.525
_POINTS_PER_MM = 72.27/25.4


def _cell_capacity(width):
    # Every line uses the declared cmtt font, not a guessed proportional width.
    return max(1, math.floor(width*_POINTS_PER_MM/_TABLE_CHARACTER_POINTS)-1)


def _plain_cell(value):
    if isinstance(value, _Tex) and value.plain_text is not None:
        return value.plain_text
    return str(value)


def _cell_lines(value, width):
    text = _plain_cell(value)
    capacity = _cell_capacity(width)
    lines = []
    while len(text) > capacity:
        boundary = text.rfind(' ', 0, capacity)
        end = boundary+1 if boundary > 0 else capacity
        lines.append(text[:end])
        text = text[end:]
    lines.append(text)
    return lines


def _table_row_parts(row, widths, budget):
    cells = [_cell_lines(value, width) for value, width in zip(row, widths)]
    maximum = max(map(len, cells))
    # Leave room for the explicit continuation marker; split any large column.
    continuation = _cell_lines('(continued)', widths[0])
    per_part = budget-len(continuation)
    if per_part < 1:
        raise ValueError('Table column and line budget cannot fit a continuation marker')
    prefixes = [value.prefix if isinstance(value, _Tex) else '' for value in row]
    for start in range(0, maximum, per_part):
        part = [lines[start:start+per_part] or [''] for lines in cells]
        if start:
            data = [] if part[0] == [''] else part[0]
            part[0] = continuation+data
        yield part, prefixes if start == 0 else ['']*len(row)


def _table_parts(rows, widths, budget):
    pages, page, used = [], [], 0
    for row in rows:
        for cells, prefixes in _table_row_parts(row, widths, budget):
            height = max(map(len, cells))
            if page and used+height > budget:
                pages.append(page)
                page, used = [], 0
            page.append((cells, prefixes))
            used += height
    if page:
        pages.append(page)
    return pages


def _boxed_cell(lines, prefix=''):
    # Explicit fixed-width line boxes make the Python height bound match TeX.
    anchor = r'\smash{'+prefix+'}' if prefix else ''
    return anchor+r'\newline{}'.join(r'\mbox{'+escape(line)+'}' for line in lines)


def _table_page(title, page, headings, widths, index, count):
    lines = [r'\par\noindent\textbf{'+escape(title)+f' ({index+1}/{count})'+'}',
             r'\par\medskip\begingroup\setlength{\tabcolsep}{3pt}',
             r'\fontfamily{cmtt}\fontsize{9}{11}\selectfont\frenchspacing',
             r'\noindent\begin{tabular}{@{}'+''.join(f'p{{{width}mm}}' for width in widths)+'@{}}',
             ' & '.join(_boxed_cell(_cell_lines(heading, width)) for heading, width in zip(headings, widths))+r'\\\hline']
    for cells, prefixes in page:
        lines.append(' & '.join(_boxed_cell(cell, prefix) for cell, prefix in zip(cells, prefixes))+r'\\')
    lines.extend([r'\end{tabular}', r'\par\endgroup\normalsize'])
    return '\n'.join(lines)


def table_pages(title, rows, headings, widths, line_budget=42):
    """Paginate fixed-metric cmtt line boxes; split long data in any column."""
    pages = _table_parts(rows, widths, line_budget)
    return [_table_page(title, page, headings, widths, index, len(pages)) for index, page in enumerate(pages)]



def _next_member(edge, locations, box, member, offset, step, positions):
    next_box, next_member = locations.get(edge['source'], ('', 0))
    return next_box == box and next_member == member+step*offset and edge['positions'] == positions


def _member_run(operands, start, locations):
    edge = operands[start]
    box, member = locations.get(edge['source'], ('', 0))
    if not box or start+1 >= len(operands):
        return start, None, box, member
    next_box, next_member = locations.get(operands[start+1]['source'], ('', 0))
    if next_box != box:
        return start, None, box, member
    step = next_member-member
    end = start
    if step in (-1, 1):
        while end+1 < len(operands) and _next_member(operands[end+1], locations, box, member, end+1-start, step, edge['positions']):
            end += 1
    return end, step, box, member


def _fragment(edge, index, references):
    source = edge['source']
    if references:
        source = references.get(source, source)
    return f'{index+1}: {source}[{selections(edge["positions"])}]'


def input_fragments(operands, locations, references=None):
    """Compact consecutive bundle members without losing fragment boundaries."""
    result, index = [], 0
    while index < len(operands):
        edge = operands[index]
        end, step, box, member = _member_run(operands, index, locations)
        if end-index >= 2:
            result.append(f'{index+1}..{end+1}: {box}.members[{member}:{step}:{member+step*(end-index)}], each [{selections(edge["positions"])}]')
            index = end+1
        else:
            result.append(_fragment(edge, index, references))
            index += 1
    return '; '.join(result) or '(no input fragments)'



def member_pages(ir, registry, locations, options):
    stages = {}
    references={node['id']:'n'+str(index) for index,node in enumerate(ir['nodes'])}
    references.update({node['id']:'I'+str(index) for index,node in enumerate(ir['inputs'])})
    for ordinal, node in enumerate(ir['nodes']):
        box, member = locations.get(node['id'], ('', 1))
        fragments = input_fragments(node['operands'], locations, references)
        prefix = r'\hypertarget{'+options.get('anchorPrefix','diagram')+'-member-'+str(ordinal)+'}{}'
        plain = f'{ordinal}: {node["id"]}'
        identity = _Tex(prefix+wrapped(plain), plain_text=plain, prefix=prefix)
        stages.setdefault(node['round'], []).append((identity,
            f'{box}/{member}', f'{node["input_bits"]}/{node["bits"]}', operation(node, registry), fragments))
    output = []
    for stage, rows in sorted(stages.items()):
        pages = table_pages(f'Round {stage}: {len(rows)} native operations', rows,
                            ['Ordinal / identity', 'Box/member', 'In/out bits', 'Operation / parameters', 'Ordered input fragments'],
                            [32, 19, 16, 33, 66], options.get('tableLineBudget', 42))
        if pages:pages[0]=r"\hypertarget{"+options.get("anchorPrefix","diagram")+"-round-"+str(stage)+"}{}"+pages[0]
        output.extend(pages)
    return output


def parameter_pages(parameters, options):
    rows = []
    for reference, kind, description in parameters.values():
        if kind in ('cipher_output', 'intermediate_output'):
            rows.append((reference, kind + ' tag', description[0]))
        elif kind == 'sbox':
            rows.append((reference, f'SBOX: {len(description)} entries', ''))
            for start in range(0, len(description), 16):
                rows.append((reference, f'indices {start}..{min(start + 15, len(description) - 1)}',
                             ','.join(map(str, description[start:start + 16]))))
        else:
            rows.append((reference, kind, json.dumps(description, separators=(',', ':'))))
    return table_pages('Native parameter definitions', rows, ['Reference', 'Type / index', 'Values'],
                       [18, 40, 106], options.get('tableLineBudget', 42)) if rows else []


def _overview_options(options):
    mode = options.get('stageMode', 'round')
    if mode not in ('round', 'layer'):
        raise ValueError('Invalid TikZ stageMode')
    count = options.get('overviewStagesPerPanel', 6)
    if type(count) is not int or not 1 <= count <= 12:
        raise ValueError('Invalid overviewStagesPerPanel')
    return mode, count


def _stage_assignments(ir, mode):
    ranks = {item['id']: 0 for item in ir['inputs']}
    stages = {}
    if mode == 'round':
        stages = {index: [] for index in range(ir['rounds'])}
    assignments = {item['id']: 'input:'+item['id'] for item in ir['inputs']}
    for node in ir['nodes']:
        rank = 1+max([ranks[edge['source']] for edge in node['operands']] or [0])
        ranks[node['id']] = rank
        stage = node['round'] if mode == 'round' else rank
        assignments[node['id']] = stage
        stages.setdefault(stage, []).append(node)
    return stages, assignments


def _stage_edges(ir, assignments):
    edges = {}
    for node in ir['nodes']:
        for edge in node['operands']:
            source, target = assignments[edge['source']], assignments[node['id']]
            if source != target:
                edges.setdefault((source, target), set()).update((edge['source'], position) for position in edge['positions'])
    return edges


def _stage_summary(nodes, registry):
    patterns = Counter(operation(node, registry, short=True) for node in nodes)
    summary = '; '.join(f'{label} x{count}' for label, count in list(patterns.items())[:3])
    if len(patterns) > 3:
        summary += f'; {len(patterns)-3} additional parameter patterns'
    return summary


def _stage_heading(ir, stage, nodes, mode, options):
    prefix = options.get('anchorPrefix', 'diagram')
    if mode == 'round':
        target = prefix+'-round-'+str(stage)
    else:
        target = prefix+'-member-'+str(ir['nodes'].index(nodes[0]))
    heading = escape(mode)+' '+str(stage)
    if options.get('view', 'overview-detail') != 'overview' and nodes:
        heading = r'\hyperlink{'+target+'}{'+heading+'}'
    return heading


def _adjacent_edges(visible, edges):
    return [(source, target, bits) for (source, target), bits in edges.items()
            if source in visible and target in visible and visible.index(target) == visible.index(source)+1]


def _boundary_text(visible, edges, mode):
    ingress = [(str(source), str(target), str(len(bits))) for (source, target), bits in edges.items()
               if target in visible and source not in visible]
    if not ingress:
        return None
    text = escape('; '.join(f'{source} -> {mode} {target}: {bits} distinct referenced bits' for source, target, bits in ingress))
    return r'\par\small Boundary inputs: '+text.replace(' -> ', r' $\to$ ')+r'\par\normalsize'


def _overview_panel(ir, stages, visible, edges, mode, registry, options):
    lines = [r'\par\noindent\textbf{Computation overview: '+str(len(ir['nodes']))+' native operations}',
             r'\par These boxes are '+mode+' summaries, not individual operations. Select overview-detail or detail for every native identity and ordered input fragment.',
             r'\par Adjacent-stage dependencies are drawn below; the complete cross-stage dependency table follows.',
             r'\par\medskip\begin{tikzpicture}[>=stealth]']
    for index, stage in enumerate(visible):
        heading = _stage_heading(ir, stage, stages[stage], mode, options)
        summary = _stage_summary(stages[stage], registry)
        lines.append(fr'\node[draw,align=left,text width=100mm,font=\small] (S{stage}) at (0,{-2.4*index}) {{{heading}: {len(stages[stage])} operations\\{escape(summary)}}};')
    for source, target, bits in _adjacent_edges(visible, edges):
        lines.append(fr'\draw[->] (S{source}.east) to[bend left=25] node[right,font=\scriptsize] {{{len(bits)} bits}} (S{target}.east);')
    lines.append(r'\end{tikzpicture}')
    boundary = _boundary_text(visible, edges, mode)
    if boundary:
        lines.append(boundary)
    return '\n'.join(lines)


def overview(ir, registry, options):
    mode, count = _overview_options(options)
    stages, assignments = _stage_assignments(ir, mode)
    edges = _stage_edges(ir, assignments)
    ordered = sorted(stages)
    output = [_overview_panel(ir, stages, ordered[start:start+count], edges, mode, registry, options)
              for start in range(0, len(ordered), count)]
    rows = [(str(source), str(target), str(len(bits))) for (source, target), bits in edges.items()]
    output.extend(table_pages('Complete cross-stage dependencies', rows,
                              ['Source input / stage', 'Destination stage', 'Distinct referenced bits'],
                              [76, 45, 45], options.get('tableLineBudget', 42)))
    return output



def _presentation_options(options):
    view = options.get('view', 'overview-detail')
    if view not in ('overview', 'detail', 'overview-detail', 'wires'):
        raise ValueError('Invalid TikZ view')
    prefix = options.get('anchorPrefix', 'diagram')
    if not isinstance(prefix, str) or not re.fullmatch('[A-Za-z0-9-]+', prefix):
        raise ValueError('Invalid TikZ anchorPrefix')
    if type(options.get('audit', False)) is not bool:
        raise ValueError('Invalid TikZ audit option')
    budget, maximum = options.get('tableLineBudget', 42), options.get('maxPages', 2048)
    if type(budget) is not int or not 8 <= budget <= 100 or type(maximum) is not int or maximum < 1:
        raise ValueError('Invalid readable TikZ pagination')
    return view, budget, maximum


def _member_locations(cells):
    locations = {}
    for (row, col), cell in cells.items():
        definition = cell.get('definition', {})
        for index, member in enumerate(definition.get('members', [definition])):
            if 'id' in member and member.get('kind', 'native') != 'input':
                locations[member['id']] = (f'D{row}:{col}', index+1)
    return locations


def _audit_pages(cells, budget):
    rows = [(f'D{row}:{col}', json.dumps(cell['definition'], separators=(',', ':')))
            for (row, col), cell in sorted(cells.items()) if 'definition' in cell]
    return table_pages('Optional audit: complete local definitions', rows, ['Box', 'Local definition'], [20, 145], budget)


def _presentation_pages(ir, cells, wire_panels, parameters, options, view, budget):
    registry = {key: value[0] for key, value in parameters.items()}
    pages = []
    if view in ('overview', 'overview-detail'):
        pages.extend(overview(ir, registry, options))
    if view == 'wires':
        pages.extend(wire_panels)
    include_members = view in ('detail', 'overview-detail', 'wires') and options.get('legend', 'readable') != 'none'
    if include_members:
        pages.extend(member_pages(ir, registry, _member_locations(cells), options))
        pages.extend(parameter_pages(parameters, options))
    if options.get('audit', False) or options.get('legend') == 'audit':
        pages.extend(_audit_pages(cells, budget))
    return pages


def _presentation_header(ir, options=None):
    if (options or {}).get('layoutSource') == 'human':
        return (r'\par\noindent\textbf{Consolidated manual synthesis: '+str(len(ir['nodes']))+' native operations}'
                +'\n'+r'\par Wire placement is reused from the verified manual ASCII strategy. Local tables retain native widths and parameters; JOIN/SELECT boxes expose ordered word projections. OUT, OBS and DEAD identify final, observation and discarded-value sinks.'+'\n')
    return (r'\par\noindent\textbf{Typed native computation: '+str(len(ir['nodes']))+' operations, '+str(ir['rounds'])+' rounds}'
            +'\n'+r'\par Detail boxes and members preserve the complete computation. Input references I0,I1,... follow declared input order; n0,n1,... denote native ordinals in the detail tables. Input fragments are concatenated in order; native arity and widths determine logical operands. Stride a:s:b denotes inclusive positions a,a+s,...,b; repeats remain explicit. The typed ASCII source retains full audit data.'+'\n')


def present(ir, cells, wire_panels, options):
    view, budget, maximum = _presentation_options(options)
    parameters = parameter_registry(ir)
    pages = _presentation_pages(ir, cells, wire_panels, parameters, options, view, budget)
    inputs = [('I'+str(index)+': '+item['id'], str(item['bits']), item['role']) for index, item in enumerate(ir['inputs'])]
    input_pages = table_pages('Declared inputs', inputs, ['Input index / identity', 'Bits', 'Role'], [85, 20, 60], budget)
    all_pages = input_pages+pages
    if len(all_pages) > maximum:
        raise ValueError(f'Readable TikZ needs {len(all_pages)} pages; increase maxPages or select a view')
    separator = '\n'+(r'\clearpage' if options.get('pageBreaks', True) else r'\par\bigskip')+'\n'
    navigation = r'\providecommand{\hypertarget}[2]{#2}'+r'\providecommand{\hyperlink}[2]{#2}'+'\n'
    # Input declarations have their own measured table pages, so a detailed
    # first table or wire panel cannot overflow beneath an arbitrary intro.
    return navigation+_presentation_header(ir, options)+separator.join(all_pages)
