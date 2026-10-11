"""Generic typed DAG diagrams. Layout is separate from executable semantics.

Bit positions follow CLAASP's MSB-first convention. Native descriptions are
retained verbatim; unsupported executable operations fail explicitly. No cipher
names or reference diagrams participate in layout or state inference.
"""
import copy
import json
from claasp.cipher import Cipher

SCHEMA = 'claasp-diagrams/1'

def validate_native_component(n):
    d = n['description']; bits = n['bits']; input_bits = n['input_bits']; typ = n['type']
    integer = lambda v: type(v) is int and abs(v) <= 2**53-1
    def require(ok):
        if not ok: raise ValueError(f"Invalid or unsupported native {typ} description/width: {n['id']}")
    if typ == 'word_operation':
        op = d[0] if d else None
        if op in {'XOR','AND','OR','MODADD','MODSUB','MODMUL'}:
            arithmetic = op.startswith('MOD')
            require(len(d) == (3 if arithmetic else 2) and integer(d[1]) and d[1] >= 1 and input_bits == d[1]*bits)
            if arithmetic: require(d[2] is None or integer(d[2]) and d[2] > 0)
        elif op in {'ROTATE','SHIFT'}: require(len(d)==2 and integer(d[1]) and input_bits==bits)
        elif op in {'NOT','REVERSE'}: require(len(d)==2 and type(d[1]) is int and d[1]==0 and input_bits==bits)
        else: require(False)
    elif typ == 'constant':
        import re
        require(input_bits==0 and len(d)==1 and isinstance(d[0],str) and re.fullmatch(r'0x[0-9a-f]+', d[0], re.I) is not None)
        require(int(d[0],16) < 2**bits)
    elif typ in {'intermediate_output','cipher_output'}: require(input_bits==bits and len(d)==1 and isinstance(d[0],str))
    elif typ == 'sbox': require(input_bits<=20 and len(d)==2**input_bits and all(integer(v) and 0<=v<2**bits for v in d))
    elif typ == 'permutation':
        require(len(d)==2 and isinstance(d[0],list) and integer(d[1]) and d[1]>0)
        p,w=d;require(input_bits==bits and bits%w==0 and len(p)==bits//w and all(integer(v) for v in p) and sorted(p)==list(range(len(p))))
    elif typ == 'linear_layer': require(len(d)==input_bits and all(isinstance(row,list) and len(row)==bits and all(type(v) is int and v in (0,1) for v in row) for row in d))
    elif typ == 'mix_column':
        require(len(d)==3)
        matrix,polynomial,w=d; require(integer(w) and 1<=w<=52 and integer(polynomial) and polynomial>=0 and (polynomial==0 or 2**w<=polynomial<2**(w+1)) and input_bits%w==0 and bits%w==0)
        require(isinstance(matrix,list) and len(matrix)==bits//w and all(isinstance(row,list) and len(row)==input_bits//w and all(integer(v) and (polynomial==0 or 0<=v<2**w) for v in row) for row in matrix))
    else: require(False)



def validate(ir):
    if ir.get('schema') != SCHEMA:
        raise ValueError('Unsupported diagram schema')
    if type(ir.get('output_bits')) is not int or ir['output_bits'] <= 0:
        raise ValueError('Missing or invalid output width')
    known = {}
    for item in ir['inputs']:
        if item['id'] in known or type(item['bits']) is not int or item['bits'] <= 0:
            raise ValueError('Invalid or duplicate input')
        known[item['id']] = item['bits']
    last_round = -1
    for n in ir['nodes']:
        if n['id'] in known or type(n['bits']) is not int or n['bits'] <= 0 or type(n['round']) is not int or n['round'] < 0 or n['round'] < last_round or type(n['input_bits']) is not int or n['input_bits'] < 0 or not isinstance(n['description'], list):
            raise ValueError('Invalid node identity, width or round order')
        last_round = n['round']
        total = 0
        for edge in n['operands']:
            if edge['source'] not in known:
                raise ValueError('Unknown, forward or cyclic bit link')
            positions = edge['positions']
            if not isinstance(positions, list) or any(type(b) is not int or b < 0 or b >= known[edge['source']] for b in positions):
                raise ValueError('Invalid bit selection')
            total += len(positions)
        if total != n['input_bits']:
            raise ValueError('Input width disagrees with ordered bit links')
        validate_native_component(n)
        known[n['id']] = n['bits']
    outputs = [n for n in ir['nodes'] if n['type'] == 'cipher_output']
    if len(outputs) != 1 or outputs[0]['bits'] != ir['output_bits']:
        raise ValueError('Require one explicitly sized native cipher output')
    if type(ir['rounds']) is not int or ir['rounds'] <= 0 or last_round >= ir['rounds']:
        raise ValueError('Round outside declared range')
    return ir


def from_cipher(cipher, *, roles=None):
    d = cipher.as_python_dictionary()
    roles = dict(getattr(cipher, "diagram_input_roles", {})) if roles is None else roles
    ir = {'schema': SCHEMA, 'name': cipher.family_name, 'cipher_type': d['cipher_type'],
          'inputs': [{'id': name, 'bits': bits, 'role': roles.get(name, 'unspecified')}
                     for name, bits in zip(d['cipher_inputs'], d['cipher_inputs_bit_size'])],
          'output_bits': d['cipher_output_bit_size'], 'rounds': d['cipher_number_of_rounds'], 'nodes': []}
    for r, components in enumerate(d['cipher_rounds']):
        for c in components:
            ir['nodes'].append({'id': c['id'], 'type': c['type'], 'bits': c['output_bit_size'],
                                'round': r, 'input_bits': c['input_bit_size'],
                                'operands': [{'source': a, 'positions': copy.deepcopy(b)} for a,b in
                                             zip(c['input_id_link'], c['input_bit_positions']) if b],
                                'description': copy.deepcopy(c['description'])})
    return validate(ir)


def to_cipher(ir):
    validate(ir)
    cipher = Cipher(ir['name'], ir['cipher_type'], [i['id'] for i in ir['inputs']],
                    [i['bits'] for i in ir['inputs']], ir['output_bits'])
    cipher.diagram_input_roles = {i['id']: i['role'] for i in ir['inputs']}
    links = {i['id']: i['id'] for i in ir['inputs']}
    current_round = -1
    for n in ir['nodes']:
        while current_round < n['round']:
            cipher.add_round(); current_round += 1
        ids = [links[e['source']] for e in n['operands']]
        pos = [e['positions'] for e in n['operands']]
        desc = n['description']; typ = n['type']; bits = n['bits']
        if typ == 'constant':
            component = cipher.add_constant_component(bits, int(desc[0], 0))
        elif typ == 'word_operation':
            op = desc[0].lower()
            if op not in {'xor','and','or','not','modadd','modsub','modmul','rotate','shift','reverse','variable_rotate','variable_shift'}:
                raise ValueError(f'Unsupported executable word operation: {op}')
            args = [ids, pos, bits]
            if op in {'rotate','shift','variable_rotate','variable_shift'}: args.append(desc[1])
            if op in {'modadd','modsub','modmul'}: args.append(desc[2] if len(desc)>2 else None)
            component = getattr(cipher, f'add_{op}_component')(*args)
        elif typ in {'sbox','linear_layer','mix_column','fsr'}:
            component = getattr(cipher, f'add_{typ}_component')(ids,pos,bits,desc)
        elif typ == 'permutation':
            component = cipher.add_permutation_component(ids,pos,bits,desc[0],desc[1])
        elif typ == 'cipher_output':
            component = cipher.add_cipher_output_component(ids,pos,bits)
        elif typ == 'intermediate_output':
            component = cipher.add_intermediate_output_component(ids,pos,bits,desc[0])
        else:
            raise ValueError(f'Unsupported executable component type: {typ}')
        links[n['id']] = component.id
    while current_round < ir['rounds']-1:
        cipher.add_round(); current_round += 1
    cipher.diagram_source_ids = links
    return cipher


def to_records(ir):
    """Lossless, visible ASCII DAG exchange; JSON fields are explicit semantics.

    This first typed dialect is not a legacy glyph-grid layout. The builder's
    typed importer parses these visible records without an embedded graph blob.
    """
    validate(ir)
    header = {k: v for k,v in ir.items() if k not in {'inputs','nodes'}}
    lines = ['+ CLAASP-DIAGRAMS 1 +', '| primitive '+json.dumps(header,sort_keys=True)]
    lines += ['| input '+json.dumps(i,sort_keys=True) for i in ir['inputs']]
    for n in ir['nodes']:
        lines += ['+ node '+json.dumps(n,sort_keys=True)]
    return '\n'.join(lines)+'\n+ END +\n'


def from_records(text):
    lines = text.splitlines()
    if not lines or lines[0] != '+ CLAASP-DIAGRAMS 1 +' or lines[-1] != '+ END +':
        raise ValueError('Invalid typed ASCII framing')
    ir = None; inputs = []; nodes = []
    for line in lines[1:-1]:
        if line.startswith('| primitive ') and ir is None: ir = json.loads(line[12:])
        elif line.startswith('| input '): inputs.append(json.loads(line[8:]))
        elif line.startswith('+ node '): nodes.append(json.loads(line[7:]))
        else: raise ValueError('Unknown or duplicate ASCII record')
    if ir is None: raise ValueError('Missing primitive record')
    ir['inputs'] = inputs; ir['nodes'] = nodes
    return validate(ir)


def layout(ir):
    """Deterministic dependency layers; no name-based placement decisions."""
    validate(ir)
    depth = {i['id']: 0 for i in ir['inputs']}; rows = {}
    for n in ir['nodes']:
        depth[n['id']] = 1+max([depth[e['source']] for e in n['operands']] or [0])
    for identity, layer in depth.items(): rows.setdefault(layer, []).append(identity)
    return {identity: {'layer': layer, 'slot': slot} for layer, ids in rows.items() for slot, identity in enumerate(ids)}


def to_layered_tikz(ir, *, layer_spacing=2, slot_spacing=3):
    positions = layout(ir); aliases = {identity: f'n{i}' for i, identity in enumerate(positions)}
    def escape(s):
        return ''.join({'_':r'\_', '%':r'\%', '&':r'\&', '#':r'\#', '{':r'\{', '}':r'\}', '\\':r'\textbackslash{}', '$':r'\$', '^':r'\textasciicircum{}', '~':r'\textasciitilde{}'}.get(c,c) for c in str(s))
    lines = [r'\begin{tikzpicture}[>=stealth, every node/.style={draw,align=center}]']
    for identity,p in positions.items():
        lines.append(fr'\node ({aliases[identity]}) at ({p["slot"]*slot_spacing},{-p["layer"]*layer_spacing}) {{{escape(identity)}}};')
    for n in ir['nodes']:
        for index,e in enumerate(n['operands']):
            label = escape(f'{index}: {e["positions"]}')
            lines.append(fr'\draw[->] ({aliases[e["source"]]}) -- node[draw=none,fill=white,font=\tiny] {{{label}}} ({aliases[n["id"]]});')
    return '\n'.join(lines+[r'\end{tikzpicture}'])


def state_view(ir, *, shape=None):
    """Declared intermediate outputs only; a flat fallback exposes ambiguity."""
    validate(ir)
    stages = []
    for n in ir['nodes']:
        if n['type'] not in {'intermediate_output','cipher_output'}: continue
        positions = [(e['source'],b) for e in n['operands'] for b in e['positions']]
        if shape is not None and (len(shape)!=2 or any(type(x) is not int or x<=0 for x in shape) or shape[0]*shape[1]!=len(positions)):
            raise ValueError('Explicit shape must cover all selected state bits')
        stages.append({'id':n['id'],'round':n['round'],'tag':n['description'],
                       'shape':list(shape) if shape else [1,len(positions)],
                       'geometry':'explicit' if shape else 'ambiguous-flat-fallback', 'ordered_bits':positions})
    return stages


def _glyph_request(request, *, node="node", timeout=30):
    """Invoke the bundled shared builder strategy with bounded execution."""
    import pathlib
    import subprocess
    script = pathlib.Path(__file__).with_name("diagram_builder") / "tools" / "typed-glyph-cli.mjs"
    try:
        result = subprocess.run([node, str(script)], input=json.dumps(request), text=True,
                                capture_output=True, timeout=timeout, check=True)
    except FileNotFoundError as error:
        raise RuntimeError("Glyph diagrams require Node.js on PATH (tested with Node 24)") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Shared glyph synthesis exceeded its execution bound") from error
    except subprocess.CalledProcessError as error:
        raise ValueError("Invalid or unsupported glyph diagram: " + error.stderr[-2000:]) from error
    return result.stdout


def to_ascii(ir, *, node="node", timeout=30):
    """Emit actual builder-importable glyphs; local annotations contain no edges."""
    if not isinstance(ir, dict):
        ir = from_cipher(ir)
    validate(ir)
    return _glyph_request({"action":"ascii", "ir":ir}, node=node, timeout=timeout)


def from_ascii(text, *, node="node", timeout=30):
    """Parse actual glyph wires, or explicitly framed legacy typed records."""
    if text.startswith("+ CLAASP-DIAGRAMS 1 +"):
        return from_records(text)
    return validate(json.loads(_glyph_request({"action":"parse", "text":text}, node=node, timeout=timeout)))


def to_tikz(ir, *, node="node", timeout=30, **options):
    """Render the same shared glyph layout; spacing, labels and wires selectable."""
    if not isinstance(ir, dict):
        ir = from_cipher(ir)
    validate(ir)
    return _glyph_request({"action":"tikz", "ir":ir, "options":options}, node=node, timeout=timeout)

def evaluate_state_values(cipher, inputs):
    """Native component values keyed by source identities; no cipher adapters."""
    evaluated = cipher.evaluate(inputs, intermediate_output=True)
    if not isinstance(evaluated, tuple) or len(evaluated) != 3:
        raise ValueError('Native evaluator did not expose component traces')
    native={**dict(zip(cipher.inputs, inputs)), **{identity: pair[1] for identity,pair in evaluated[2].items()}}
    links=getattr(cipher, 'diagram_source_ids', None)
    return {original:native[generated] for original,generated in links.items()} if links else native


def state_snapshots(ir, *, mode='declared', word_bits=1, columns=None, order='source', values=None, comparison=None):
    """Explicit outputs or generic live-value cuts by dependency layer/round.

    With no column annotation, shape is an ambiguous flat fallback. A cut is
    live native values, not an inferred algorithm-specific state matrix.
    """
    validate(ir)
    if mode not in {'declared','layer','round'} or order not in {'source','reverse'}:
        raise ValueError('Unknown state snapshot mode or order')
    if type(word_bits) is not int or word_bits<=0 or columns is not None and (type(columns) is not int or columns<=0):
        raise ValueError('Positive explicit word width/columns required')
    all_nodes=ir['inputs']+ir['nodes']; widths={n['id']:n['bits'] for n in all_nodes}
    if mode=='declared':
        groups=[(n['id'], n['round'], [(e['source'],b) for e in n['operands'] for b in e['positions']]) for n in ir['nodes'] if n['type'] in {'intermediate_output','cipher_output'}]
    else:
        ranks={i['id']:(0 if mode=='layer' else -1) for i in ir['inputs']}
        layers=layout(ir) if mode=='layer' else None
        ranks.update({n['id']:(layers[n['id']]['layer'] if mode=='layer' else n['round']) for n in ir['nodes']})
        consumers={identity:[] for identity in ranks}
        for n in ir['nodes']:
            for e in n['operands']:consumers[e['source']].append(ranks[n['id']])
        final=next(n['id'] for n in ir['nodes'] if n['type']=='cipher_output')
        groups=[]
        for cut in sorted(set(ranks.values())):
            selected=[n for n in all_nodes if ranks[n['id']]<=cut and (any(c>cut for c in consumers[n['id']]) or n['id']==final)]
            groups.append((f'{mode}-{cut}',cut,[(n['id'],b) for n in selected for b in range(n['bits'])]))
    snapshots=[]
    for identity,stage,positions in groups:
        if order=='reverse':positions=list(reversed(positions))
        if len(positions)%word_bits:raise ValueError('Explicit word width must divide selected state bits')
        words=[]
        for start in range(0,len(positions),word_bits):
            bits=positions[start:start+word_bits];value=delta=0;known=values is not None;difference=comparison is not None and known
            for source,bit in bits:
                if known:
                    if source not in values or type(values[source]) is not int or not 0<=values[source]<2**widths[source]:raise ValueError('Missing or out-of-range component value')
                    value=(value<<1)|((values[source]>>(widths[source]-1-bit))&1)
                if difference:
                    if source not in comparison or type(comparison[source]) is not int or not 0<=comparison[source]<2**widths[source]:raise ValueError('Missing or out-of-range comparison value')
                    delta=(delta<<1)|(((values[source]^comparison[source])>>(widths[source]-1-bit))&1)
            words.append({'positions':bits,'value':value if known else None,'difference':delta if difference else None,'active':bool(delta if difference else value) if known else None})
        cols=columns or max(1,len(words));snapshots.append({'id':identity,'stage':stage,'mode':mode,'order':order,'word_bits':word_bits,'columns':cols,'rows':(len(words)+cols-1)//cols,'geometry':'explicit-columns' if columns else 'ambiguous-flat-fallback','words':words})
    return snapshots


def state_ascii(ir, **options):
    """Render snapshots with hex values or explicit unknowns; * marks activity."""
    lines=[]
    for frame in state_snapshots(ir, **options):
        lines.append(f"{frame['id']} ({frame['mode']}, {frame['geometry']}, order={frame['order']}, word_bits={frame['word_bits']})")
        words=frame['words'];digits=(frame['word_bits']+3)//4;size=max(5,digits+3)
        border='+'+('+'.join('-'*size for _ in range(frame['columns'])))+'+'
        for row in range(frame['rows']):
            lines.append(border);cells=[]
            for col in range(frame['columns']):
                index=row*frame['columns']+col
                if index>=len(words):cells.append(' '*size);continue
                w=words[index];v=w['difference'] if w['difference'] is not None else w['value']
                text='?' if v is None else f'{v:0{digits}x}';text+= '*' if w['active'] else ' '
                cells.append(text.center(size))
            lines.append('|'+'|'.join(cells)+'|')
        lines.append(border);lines.append('')
    return '\n'.join(lines)


def state_tikz(ir, *, cell_width=1, cell_height=.5, rows_per_panel=24,
               columns_per_panel=12, frame_range=None, page_breaks=True,
               max_panels=256, **options):
    """Paginated generic state cells; cuts never reinterpret state geometry.

    Fragment output belongs directly in a LaTeX document body, not one float.
    frame_range is a half-open range in the generated snapshot sequence.
    """
    if cell_width<=0 or cell_height<=0:raise ValueError('Positive cell spacing required')
    if any(type(n) is not int or n<=0 for n in [rows_per_panel,columns_per_panel,max_panels]) or type(page_breaks) is not bool:raise ValueError('Invalid state pagination options')
    frames=state_snapshots(ir, **options)
    if frame_range is not None:
        if not isinstance(frame_range,(list,tuple)) or len(frame_range)!=2 or any(type(n) is not int for n in frame_range) or not 0<=frame_range[0]<frame_range[1]<=len(frames):raise ValueError('Invalid state frame range')
        frames=frames[frame_range[0]:frame_range[1]]
    count=sum(((f['rows']+rows_per_panel-1)//rows_per_panel)*((f['columns']+columns_per_panel-1)//columns_per_panel) for f in frames)
    if count>max_panels:raise ValueError(f'State needs {count} panels; supply frame_range or larger max_panels')
    escaped=lambda text: ''.join({'_':r'\_', '%':r'\%', '&':r'\&', '#':r'\#', '{':r'\{', '}':r'\}', '\\':r'\textbackslash{}', '$':r'\$', '^':r'\textasciicircum{}', '~':r'\textasciitilde{}'}.get(c,c) for c in str(text))
    wrapped=lambda text: ''.join(escaped(c)+(r'\allowbreak{}' if (i+1)%12==0 else '') for i,c in enumerate(str(text)))
    panels=[]
    for frame in frames:
        for top in range(0,frame['rows'],rows_per_panel):
            for left in range(0,frame['columns'],columns_per_panel):
                bottom=min(frame['rows'],top+rows_per_panel);right=min(frame['columns'],left+columns_per_panel)
                lines=[r'\begin{tikzpicture}[font=\scriptsize]'];legend=[]
                title=f"{frame['id']}: {frame['geometry']}, {frame['word_bits']} bits/word, order {frame['order']}"
                lines.append(fr"\node[anchor=south west,align=left,text width={columns_per_panel*cell_width}cm] at (0,.95) {{{wrapped(title)}}};")
                lines.append(fr"\node[anchor=west,font=\tiny] at (0,.6) {{original cell rows {top}--{bottom-1}, columns {left}--{right-1}; indices retained}};")
                for index,w in enumerate(frame['words']):
                    row,col=divmod(index,frame['columns'])
                    if not top<=row<bottom or not left<=col<right:continue
                    value=w['difference'] if w['difference'] is not None else w['value'];text='?' if value is None else f"{value:0{(frame['word_bits']+3)//4}x}"
                    if len(text)>6:
                        key=f'V{index}';legend.append((key,text));text=key
                    fill='orange!25' if w['active'] else 'white'
                    lines.append(fr"\node[draw,fill={fill},minimum width={cell_width}cm,minimum height={cell_height}cm] at ({(col-left)*cell_width},{-(row-top)*cell_height}) {{{text}}};")
                    lines.append(fr"\node[font=\tiny,anchor=south] at ({(col-left)*cell_width},{-(row-top)*cell_height+cell_height/2}) {{{index}}};")
                lines.append(r'\end{tikzpicture}\par\smallskip')
                for key,text in legend:lines.append(r'{\raggedright\scriptsize\noindent\textbf{'+key+'}: '+wrapped(text)+r'\par}\smallskip')
                panels.append('\n'.join(lines))
    return ('\n'+(r'\clearpage' if page_breaks else r'\par\medskip')+'\n').join(panels)
