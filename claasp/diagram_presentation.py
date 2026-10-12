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


def operation(node, registry=None, short=False):
    kind = node.get('type', node.get('kind', ''))
    description = node.get('description', [])
    if kind == 'word_operation':
        name = description[0]
        if name in ('NOT', 'REVERSE'):
            return f'{name}/{node["bits"]}(unary)'
        parameters = str(description[1]) if name in ('ROTATE', 'SHIFT') else 'arity=' + str(description[1])
        if short and name not in ('ROTATE', 'SHIFT'):
            parameters = str(description[1])
        if len(description) > 2 and description[2] is not None:
            parameters += ',mod=' + str(description[2])
        return f'{name}/{node["bits"]}({parameters})'
    if kind == 'constant':
        value = description[0]
        if len(value) > 12:
            key = json.dumps([kind, description], separators=(',', ':'))
            reference = registry.get(key) if registry else None
            value = reference or value
        return f'CONST/{node["bits"]}={value}'
    if kind in ('cipher_output', 'intermediate_output'):
        return ('OUT' if kind == 'cipher_output' else 'OBSERVE') + '/' + str(node['bits'])
    if kind in ('input', 'join', 'selection'):
        return {'input': 'INPUT', 'join': 'PACK', 'selection': 'SELECT'}[kind] + '/' + str(node['bits'])
    reference = registry.get(json.dumps([kind, description], separators=(',', ':'))) if registry else None
    return kind.upper() + '/' + str(node['bits']) + (' ' + reference if reference else '')


def parameter_registry(ir):
    parameters = {}
    for node in ir['nodes']:
        if node['type'] not in ('word_operation', 'constant', 'cipher_output', 'intermediate_output') or (node['type'] == 'constant' and len(node['description'][0]) > 12):
            key = json.dumps([node['type'], node['description']], separators=(',', ':'))
            if key not in parameters:
                parameters[key] = (f'P{len(parameters) + 1}', node['type'], node['description'])
    return parameters


class Tex(str):
    """Escaped/generated presentation markup, never raw input data."""


def table_pages(title, rows, headings, widths, line_budget=42):
    """Paginate by estimated wrapped lines as well as native record count."""
    parts = []
    page = []
    used = 0
    for row in rows:
        visible=lambda value:re.sub(r'\\hypertarget\{[^}]*\}\{\}', '', str(value)).replace(r'\allowbreak{}','').replace(r'\_','_')
        lines = max(1, max(math.ceil(len(visible(value)) / max(8, int(width * .65)))
                           for value, width in zip(row, widths)))
        if page and used + lines > line_budget:
            parts.append(page)
            page = []
            used = 0
        # Very large fields are split into visibly numbered continuation rows.
        limit = max(80, int(widths[-1] * .65 * (line_budget - 3)))
        tail = str(row[-1])
        chunks = [tail[i:i + limit] for i in range(0, len(tail), limit)] or ['']
        for index, chunk in enumerate(chunks):
            continuation = tuple(row[:-1]) + (chunk,)
            if index:
                identifier=re.sub(r'\\hypertarget\{[^}]*\}\{\}', '', str(row[0])) if isinstance(row[0],Tex) else wrapped(row[0])
                continuation = (Tex(identifier + ' (continued)'),) + ('',) * (len(row) - 2) + (chunk,)
            estimated = max(1, math.ceil(len(chunk) / max(8, int(widths[-1] * .65))))
            if page and used + estimated > line_budget:
                parts.append(page)
                page = []
                used = 0
            page.append(continuation)
            used += max(lines if len(chunks) == 1 else estimated, 1)
    if page:
        parts.append(page)
    output = []
    for index, page in enumerate(parts):
        lines = [r'\par\noindent\textbf{' + escape(title) + f' ({index + 1}/{len(parts)})' + '}',
                 r'\par\medskip\small\setlength{\tabcolsep}{3pt}',
                 r'\begin{tabular}{@{}' + ''.join(f'p{{{width}mm}}' for width in widths) + '@{}}',
                 ' & '.join(escape(h) for h in headings) + r'\\\hline']
        lines.extend(' & '.join(str(value) if isinstance(value,Tex) else wrapped(value) for value in row) + r'\\' for row in page)
        lines.extend([r'\end{tabular}', r'\par\normalsize'])
        output.append('\n'.join(lines))
    return output


def input_fragments(operands, locations, references=None):
    """Compact consecutive bundle members without losing fragment boundaries."""
    result=[];index=0
    while index<len(operands):
        edge=operands[index];box,member=locations.get(edge['source'],('',0));end=index;step=None
        if box and index+1<len(operands):
            next_box,next_member=locations.get(operands[index+1]['source'],('',0))
            step=next_member-member if next_box==box else None
            if step in (-1,1):
                while end+1<len(operands):
                    following=operands[end+1];following_box,following_member=locations.get(following['source'],('',0))
                    if following_box!=box or following_member!=member+step*(end+1-index) or following['positions']!=edge['positions']:break
                    end+=1
        if end-index>=2:
            result.append(f'{index+1}..{end+1}: {box}.members[{member}:{step}:{member+step*(end-index)}], each [{selections(edge["positions"])}]')
            index=end+1
        else:
            source=references.get(edge['source'],edge['source']) if references else edge['source']
            result.append(f'{index+1}: {source}[{selections(edge["positions"])}]');index+=1
    return '; '.join(result) or '(no input fragments)'


def member_pages(ir, registry, locations, options):
    stages = {}
    references={node['id']:'n'+str(index) for index,node in enumerate(ir['nodes'])}
    references.update({node['id']:'I'+str(index) for index,node in enumerate(ir['inputs'])})
    for ordinal, node in enumerate(ir['nodes']):
        box, member = locations.get(node['id'], ('', 1))
        fragments = input_fragments(node['operands'], locations, references)
        identity=Tex(r'\hypertarget{'+options.get('anchorPrefix','diagram')+'-member-'+str(ordinal)+'}{}'+wrapped(f'{ordinal}: {node["id"]}'))
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
        if kind == 'sbox':
            rows.append((reference, f'SBOX: {len(description)} entries', ''))
            for start in range(0, len(description), 16):
                rows.append((reference, f'indices {start}..{min(start + 15, len(description) - 1)}',
                             ','.join(map(str, description[start:start + 16]))))
        else:
            rows.append((reference, kind, json.dumps(description, separators=(',', ':'))))
    return table_pages('Native parameter definitions', rows, ['Reference', 'Type / index', 'Values'],
                       [18, 40, 106], options.get('tableLineBudget', 42)) if rows else []


def overview(ir, registry, options):
    mode = options.get('stageMode', 'round')
    if mode not in ('round', 'layer'):
        raise ValueError('Invalid TikZ stageMode')
    count = options.get('overviewStagesPerPanel', 6)
    if type(count) is not int or count < 1 or count > 12:
        raise ValueError('Invalid overviewStagesPerPanel')
    ranks = {i['id']: 0 for i in ir['inputs']}
    stages = {round_index: [] for round_index in range(ir['rounds'])} if mode == 'round' else {}
    assignments = {i['id']: 'input:' + i['id'] for i in ir['inputs']}
    for node in ir['nodes']:
        rank = 1 + max([ranks[e['source']] for e in node['operands']] or [0])
        ranks[node['id']] = rank
        stage = node['round'] if mode == 'round' else rank
        assignments[node['id']] = stage
        stages.setdefault(stage, []).append(node)
    edges = {}
    for node in ir['nodes']:
        for edge in node['operands']:
            source, target = assignments[edge['source']], assignments[node['id']]
            if source != target:
                edges.setdefault((source, target), set()).update((edge['source'], p) for p in edge['positions'])
    output = []
    ordered = sorted(stages)
    for start in range(0, len(ordered), count):
        visible = ordered[start:start + count]
        lines = [r'\par\noindent\textbf{Computation overview: ' + str(len(ir['nodes'])) + ' native operations}',
                 r'\par These boxes are ' + mode + ' summaries, not individual operations. Select overview-detail or detail for every native identity and ordered input fragment.',
                 r'\par Adjacent-stage dependencies are drawn below; the complete cross-stage dependency table follows.',
                 r'\par\medskip\begin{tikzpicture}[>=stealth]']
        for index, stage in enumerate(visible):
            patterns = Counter(operation(node, registry, short=True) for node in stages[stage])
            summary = '; '.join(f'{op} x{n}' for op, n in list(patterns.items())[:3])
            if len(patterns) > 3:
                summary += f'; {len(patterns) - 3} additional parameter patterns'
            target=options.get('anchorPrefix','diagram')+'-round-'+str(stage) if mode=='round' else options.get('anchorPrefix','diagram')+'-member-'+str(ir['nodes'].index(stages[stage][0]))
            heading=(r'\hyperlink{'+target+'}{'+escape(mode)+' '+str(stage)+'}') if options.get('view','overview-detail')!='overview' and stages[stage] else escape(mode)+' '+str(stage)
            lines.append(fr'\node[draw,align=left,text width=100mm,font=\small] (S{stage}) at (0,{-2.4 * index}) {{{heading}: {len(stages[stage])} operations\\{escape(summary)}}};')
        for (source, target), bits in edges.items():
            if source in visible and target in visible and visible.index(target) == visible.index(source) + 1:
                lines.append(fr'\draw[->] (S{source}.east) to[bend left=25] node[right,font=\scriptsize] {{{len(bits)} bits}} (S{target}.east);')
        lines.append(r'\end{tikzpicture}')
        ingress = [(str(source), str(target), str(len(bits))) for (source, target), bits in edges.items()
                   if target in visible and source not in visible]
        if ingress:
            lines.append(r'\par\small Boundary inputs: ' + escape('; '.join(f'{s} -> {mode} {t}: {b} distinct referenced bits' for s, t, b in ingress)).replace(' -> ', r' $	o$ ') + r'\par\normalsize')
        output.append('\n'.join(lines))
    dependency_rows = [(str(source), str(target), str(len(bits)))
                       for (source, target), bits in edges.items()]
    output.extend(table_pages('Complete cross-stage dependencies', dependency_rows,
                              ['Source input / stage', 'Destination stage', 'Distinct referenced bits'],
                              [76, 45, 45], options.get('tableLineBudget', 42)))
    return output


def present(ir, cells, dimensions, wire_panels, options):
    view = options.get('view', 'overview-detail')
    if view not in ('overview', 'detail', 'overview-detail', 'wires'):
        raise ValueError('Invalid TikZ view')
    prefix=options.get('anchorPrefix','diagram')
    if not isinstance(prefix,str) or not re.fullmatch('[A-Za-z0-9-]+',prefix):raise ValueError('Invalid TikZ anchorPrefix')
    if type(options.get('audit',False)) is not bool:raise ValueError('Invalid TikZ audit option')
    budget = options.get('tableLineBudget', 42)
    maximum = options.get('maxPages', 2048)
    if type(budget) is not int or not 8 <= budget <= 100 or type(maximum) is not int or maximum < 1:
        raise ValueError('Invalid readable TikZ pagination')
    parameters = parameter_registry(ir)
    registry = {key: value[0] for key, value in parameters.items()}
    locations = {}
    for (row, col), cell in cells.items():
        definition = cell.get('definition', {})
        for index, member in enumerate(definition.get('members', [definition])):
            if 'id' in member and member.get('kind', 'native') != 'input':
                locations[member['id']] = (f'D{row}:{col}', index + 1)
    pages = []
    inputs = [('I'+str(index)+': '+i['id'], str(i['bits']), i['role']) for index,i in enumerate(ir['inputs'])]
    input_pages=table_pages('Declared inputs', inputs, ['Input index / identity', 'Bits', 'Role'], [85, 20, 60], budget)
    intro='\n'.join(input_pages)
    if view in ('overview', 'overview-detail'):
        pages.extend(overview(ir, registry, options))
    if view == 'wires':
        pages.extend(wire_panels)
    if view in ('detail', 'overview-detail', 'wires') and options.get('legend', 'readable') != 'none':
        pages.extend(member_pages(ir, registry, locations, options))
        pages.extend(parameter_pages(parameters, options))
    if options.get('audit', False) or options.get('legend')=='audit':
        rows = [(f'D{r}:{c}', json.dumps(cell['definition'], separators=(',', ':')))
                for (r, c), cell in sorted(cells.items()) if 'definition' in cell]
        pages.extend(table_pages('Optional audit: complete local definitions', rows, ['Box', 'Local definition'], [20, 145], budget))
    if len(pages) > maximum:
        raise ValueError(f'Readable TikZ needs {len(pages)} pages; increase maxPages or select a view')
    separator = '\n' + (r'\clearpage' if options.get('pageBreaks', True) else r'\par\bigskip') + '\n'
    header = (r'\par\noindent\textbf{Typed native computation: ' + str(len(ir['nodes'])) + ' operations, ' + str(ir['rounds']) + ' rounds}'
              + '\n' + r'\par Detail boxes and members preserve the complete computation. Input references I0,I1,... follow declared input order; n0,n1,... denote native ordinals in the detail tables. Input fragments are concatenated in order; native arity and widths determine logical operands. Stride a:s:b denotes inclusive positions a,a+s,...,b; repeats remain explicit. The typed ASCII source retains full audit data.' + '\n')
    navigation=r'\providecommand{\hypertarget}[2]{#2}'+r'\providecommand{\hyperlink}[2]{#2}'+'\n'
    return navigation + header + intro + r"\par\bigskip" + separator.join(pages)
