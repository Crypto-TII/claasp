"""Generic typed DAG diagrams. Layout is separate from executable semantics.

Bit positions follow CLAASP's MSB-first convention. Native descriptions are
retained verbatim; unsupported executable operations fail explicitly. No cipher
names or reference diagrams participate in layout or state inference.
"""
import copy
import json
from claasp.cipher import Cipher

from claasp.cipher_modules.diagram.validation import SCHEMA, validate as _validate, validate_native_component as _validate_native_component
from claasp.cipher_modules.diagram.validation import _native_description
from claasp.cipher_modules.diagram import states as diagram_states

RECORD_HEADER = '+ CLAASP-DIAGRAMS 1 +'


def validate(ir):
    r"""
    Validate a complete typed native computation without modifying it.

    INPUT:

    - ``ir`` -- **dictionary**; representation returned by ``from_cipher`` or ``from_ascii``

    OUTPUT:

    The same validated **dictionary**.

    RAISES:

    ``ValueError`` for invalid widths, selections, output declarations, dependency order or unsupported transforms.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import validate
        sage: checked = validate(ir)
        sage: checked['output_bits']
        32
    """
    return _validate(ir)


def validate_native_component(node):
    r"""
    Check one local native transform against the supported description grammar.

    INPUT:

    - ``node`` -- **dictionary**; native node with type, description, input/output widths and identity

    OUTPUT:

    ``None`` after successful validation.

    RAISES:

    ``ValueError`` for unsupported transforms or inconsistent local parameters.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import validate_native_component
        sage: rotation = ir['nodes'][0]
        sage: validate_native_component(rotation)
        sage: rotation['description']
        ['ROTATE', 7]
    """
    return _validate_native_component(node)


def from_cipher(cipher, *, roles=None):
    r"""
    Extract the supported native computation without choosing a drawing layout.

    Ordered native tuples/vectors and exact integer scalars become JSON-safe lists/integers.
    Binary-field entries are converted only when they are exactly zero or one in a binary linear layer.
    Conversion preserves entries and their order without changing the native source.

    This reduced-round Speck example teaches the API; it is not the full-round cipher. Names never select layout or state shape.

    Rendering options are separate from extraction: pass this result to
    ``to_ascii(ir, operator_style='symbols', wire_borders=False, alignment='left',
    layout_preference='balanced', word_bits=None)`` for the default manual body.
    ``to_ascii(ir, annotations=True)`` adds lossless local human metadata.
    ``to_audit_ascii(ir)`` retains the explicit lossless audit encoding.
    ``to_ascii(ir, format='audit')`` is its alternate entry point. Human rendering
    currently requires uniform words and supported unary/binary word
    operations; noncontiguous selections use visible selection helpers; other graphs use the audit view explicitly. ``roles={}``
    disables native interface role conventions. See ``to_ascii`` for complete
    printouts, rendering choices and work bounds.

    INPUT:

    - ``cipher`` -- **Cipher**; primitive whose complete component graph is extracted
    - ``roles`` -- **dictionary** (default: ``None``); explicit input roles, such as data/key; omitted roles reuse annotations and CLAASP block-cipher INPUT_KEY/INPUT_PLAINTEXT interface conventions; explicit dictionaries override both

    OUTPUT:

    A typed **dictionary** containing ordered input fragments, complete native descriptions, widths and numeric rounds. Missing roles are ``unspecified``.

    RAISES:

    ``ValueError`` if native descriptions or graph widths/order are unsupported or inconsistent.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: ir = from_cipher(speck, roles={'plaintext': 'data', 'key': 'key'})
        sage: [(item['id'], item['bits'], item['role']) for item in ir['inputs']]
        [('plaintext', 32, 'data'), ('key', 64, 'key')]
        sage: (ir['rounds'], len(ir['nodes']))
        (1, 7)
    """
    d = cipher.as_python_dictionary()
    if roles is None:
        from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT
        roles = {}
        # CLAASP block-cipher input designations are native interface semantics.
        # No component identity or family name participates in role extraction.
        if d['cipher_type'] == BLOCK_CIPHER:
            roles = {INPUT_KEY: 'key', INPUT_PLAINTEXT: 'data'}
        roles.update(dict(getattr(cipher, 'diagram_input_roles', {})))
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
                                'description': _native_description(c['type'], c['description'])})
    return validate(ir)


def _word_component(cipher, ids, positions, node):
    description = node['description']
    name = {'ROTATE_BY_VARIABLE_AMOUNT': 'variable_rotate',
            'SHIFT_BY_VARIABLE_AMOUNT': 'variable_shift'}.get(description[0], description[0].lower())
    allowed = {'xor', 'and', 'or', 'not', 'modadd', 'modsub', 'modmul',
               'rotate', 'shift', 'reverse', 'variable_rotate', 'variable_shift', 'idea_modmul'}
    if name not in allowed:
        raise ValueError(f'Unsupported executable word operation: {name}')
    arguments = [ids, positions, node['bits']]
    if name in {'rotate', 'shift', 'variable_rotate', 'variable_shift'}:
        arguments.append(description[1])
    if name in {'modadd', 'modsub', 'modmul', 'idea_modmul'}:
        modulus = description[2] if len(description) > 2 else None
        arguments.append(modulus)
    return getattr(cipher, f'add_{name}_component')(*arguments)


def _append_component(cipher, node, links):
    ids = [links[edge['source']] for edge in node['operands']]
    positions = [edge['positions'] for edge in node['operands']]
    description, kind, bits = node['description'], node['type'], node['bits']
    if kind == 'constant':
        return cipher.add_constant_component(bits, int(description[0], 0))
    if kind == 'word_operation':
        return _word_component(cipher, ids, positions, node)
    if kind in {'sbox', 'linear_layer', 'mix_column', 'fsr'}:
        return getattr(cipher, f'add_{kind}_component')(ids, positions, bits, description)
    if kind == 'permutation':
        return cipher.add_permutation_component(ids, positions, bits, description[0], description[1])
    if kind == 'cipher_output':
        return cipher.add_cipher_output_component(ids, positions, bits)
    if kind == 'intermediate_output':
        return cipher.add_intermediate_output_component(ids, positions, bits, description[0])
    raise ValueError(f'Unsupported executable component type: {kind}')


def to_cipher(ir):
    r"""
    Reconstruct an executable CLAASP Cipher from ordered native semantics.

    Reconstruction preserves the computation, not arbitrary original diagram placement.

    INPUT:

    - ``ir`` -- **dictionary**; supported typed representation

    OUTPUT:

    An executable **Cipher**, with ``diagram_source_ids`` mapping original identifiers to reconstructed identifiers and ``diagram_input_roles`` retaining roles.

    RAISES:

    ``ValueError`` if validation or executable-component support fails.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_cipher
        sage: rebuilt = to_cipher(ir)
        sage: hex(rebuilt.evaluate(list(map(int, [0x6574694c, 0x1918111009080100]))))
        '0x5316f627'
        sage: rebuilt.number_of_rounds
        1
    """
    validate(ir)
    cipher = Cipher(ir['name'], ir['cipher_type'], [item['id'] for item in ir['inputs']],
                    [item['bits'] for item in ir['inputs']], ir['output_bits'])
    cipher.diagram_input_roles = {item['id']: item['role'] for item in ir['inputs']}
    links = {item['id']: item['id'] for item in ir['inputs']}
    current_round = -1
    for node in ir['nodes']:
        while current_round < node['round']:
            cipher.add_round()
            current_round += 1
        component = _append_component(cipher, node, links)
        links[node['id']] = component.id
    while current_round < ir['rounds']-1:
        cipher.add_round()
        current_round += 1
    cipher.diagram_source_ids = links
    return cipher



def to_records(ir):
    r"""
    Emit explicit diagnostic JSON records in an ASCII envelope.

    INPUT:

    - ``ir`` -- **dictionary**; supported typed computation

    OUTPUT:

    A **string** of primitive/input/node records. This diagnostic format explicitly contains dependencies and is distinct from the visible-wire glyph format.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_records
        sage: records = to_records(ir)
        sage: print(records.splitlines()[0])
        + CLAASP-DIAGRAMS 1 +
        sage: print(records.splitlines()[-1])
        + END +
    """
    validate(ir)
    header = {k: v for k,v in ir.items() if k not in {'inputs','nodes'}}
    lines = [RECORD_HEADER, '| primitive '+json.dumps(header,sort_keys=True)]
    lines += ['| input '+json.dumps(i,sort_keys=True) for i in ir['inputs']]
    for n in ir['nodes']:
        lines += ['+ node '+json.dumps(n,sort_keys=True)]
    return '\n'.join(lines)+'\n+ END +\n'


def from_records(text):
    r"""
    Read the explicit diagnostic record interchange.

    INPUT:

    - ``text`` -- **string**; record envelope produced by ``to_records``

    OUTPUT:

    A validated typed **dictionary**.

    RAISES:

    ``ValueError`` for invalid framing, missing/duplicate primitive records or unsupported native semantics.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_records, from_records
        sage: parsed = from_records(to_records(ir))
        sage: [(item['id'], item['bits']) for item in parsed['inputs']]
        [('plaintext', 32), ('key', 64)]
    """
    lines = text.splitlines()
    if not lines or lines[0] != RECORD_HEADER or lines[-1] != '+ END +':
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
    r"""
    Assign deterministic dependency layers and source-order slots.

    INPUT:

    - ``ir`` -- **dictionary**; supported typed graph

    OUTPUT:

    A **dictionary** mapping each input/native identity to ``layer`` and ``slot``. This is a generic DAG placement, not inversion of an original drawing.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import layout
        sage: positions = layout(ir)
        sage: positions['plaintext']
        {'layer': 0, 'slot': 0}
        sage: positions['rot_0_0']
        {'layer': 1, 'slot': 0}
    """
    validate(ir)
    depth = {i['id']: 0 for i in ir['inputs']}; rows = {}
    for n in ir['nodes']:
        depth[n['id']] = 1+max([depth[e['source']] for e in n['operands']] or [0])
    for identity, layer in depth.items(): rows.setdefault(layer, []).append(identity)
    return {identity: {'layer': layer, 'slot': slot} for layer, ids in rows.items() for slot, identity in enumerate(ids)}


def to_layered_tikz(ir, *, layer_spacing=2, slot_spacing=3):
    r"""
    Render the diagnostic dependency-layer graph with ordered bit-link labels.

    INPUT:

    - ``ir`` -- **dictionary**; supported typed graph
    - ``layer_spacing`` -- **number** (default: ``2``); vertical layer distance
    - ``slot_spacing`` -- **number** (default: ``3``); horizontal slot distance

    OUTPUT:

    A **string** containing a TikZ picture. ``to_tikz`` provides the more readable overview/detail presentation.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_layered_tikz
        sage: picture = to_layered_tikz(ir)
        sage: print(picture.splitlines()[1])
        \node (n0) at (0,0) {plaintext};
    """
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


def _validate_state_shape(shape, bits):
    if shape is None:
        return
    if len(shape) != 2 or any(type(x) is not int or x <= 0 for x in shape):
        raise ValueError('Explicit shape must cover all selected state bits')
    if shape[0]*shape[1] != bits:
        raise ValueError('Explicit shape must cover all selected state bits')


def state_view(ir, *, shape=None):
    r"""
    Describe declared observations as ordered bit selections, with explicit shape ambiguity.

    INPUT:

    - ``ir`` -- **dictionary**; supported graph
    - ``shape`` -- **pair of integers** (default: ``None``); explicit bit-level row/column counts covering every observation

    OUTPUT:

    A **list of dictionaries** with source-bit positions, tags, rounds and geometry. Omitted shape is ``ambiguous-flat-fallback``.

    RAISES:

    ``ValueError`` if an explicit shape does not cover all selected bits.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import state_view
        sage: [(frame['round'], frame['shape'], frame['geometry']) for frame in state_view(ir)]
        [(0, [1, 16], 'ambiguous-flat-fallback'),
         (0, [1, 32], 'ambiguous-flat-fallback')]
        sage: state_view(ir, shape=(int(2), int(16)))
        Traceback (most recent call last):
        ...
        ValueError: Explicit shape must cover all selected state bits
    """
    validate(ir)
    stages = []
    for n in ir['nodes']:
        if n['type'] not in {'intermediate_output','cipher_output'}: continue
        positions = [(e['source'],b) for e in n['operands'] for b in e['positions']]
        _validate_state_shape(shape, len(positions))
        stages.append({'id':n['id'],'round':n['round'],'tag':n['description'],
                       'shape':list(shape) if shape else [1,len(positions)],
                       'geometry':'explicit' if shape else 'ambiguous-flat-fallback', 'ordered_bits':positions})
    return stages


def to_ascii(ir, *, format='human', annotations=False, word_bits=None,
             operator_style='symbols', wire_borders=False, alignment='left',
             layout_preference='balanced', strategy='semantic-auto',
             max_cells=1000000, max_calls=20000, max_grid_area=2000000,
             max_text_bytes=64000000):
    r"""
    Draw a readable, builder-importable manual block body by default.

    ``annotations=True`` appends coordinate-local native metadata for exact
    ``from_ascii`` reconstruction. Dependencies are traced from exported
    glyphs and wires; annotations contain no original graph or source links.
    ``to_audit_ascii`` and ``format='audit'`` retain the explicit audit grammar.
    Primitive names and manual references never select a layout.

    INPUT:

    - ``ir`` -- **dictionary** or **Cipher**; supported native computation
    - ``format`` -- ``'human'`` (default) or ``'audit'``
    - ``annotations`` -- **boolean** (default: ``False``); append lossless local human metadata
    - ``word_bits`` -- positive **integer** or ``None``; infer the GCD of native word-operation widths, with output width as a generic fallback
    - ``operator_style`` -- ``'symbols'`` (default) or ``'labels'``; numeric rotation/shift arrows remain explicit in both
    - ``wire_borders`` -- **boolean** (default: ``False``); draw routing-cell frames; operation frames follow the manual vocabulary
    - ``alignment`` -- ``'left'`` (default) or ``'right'``; prefer an expired operand lane, subject to liveness and ordered arithmetic
    - ``layout_preference`` -- ``'balanced'`` (default), ``'crossings'``, ``'depth'`` or ``'width'``; select among measured generic candidate layouts
    - ``strategy`` -- ``'semantic-auto'`` (default); human candidates are ``semantic-legacy``, ``semantic-ports``, ``semantic-round``, ``semantic-width``, ``semantic-depth`` and ``semantic-crossings``; ``direct-bus`` is an explicit baseline
    - ``max_cells`` -- positive **integer** (default: ``1000000``); occupied block limit
    - ``max_calls`` -- positive **integer** (default: ``20000``); native/helper word-expansion limit
    - ``max_grid_area`` -- positive **integer** (default: ``2000000``); rectangular block limit
    - ``max_text_bytes`` -- positive **integer** (default: ``64000000``); output/local verification byte limit

    OUTPUT:

    A **string** using the manual 5-line by 11-character block grammar.
    ``o`` is a fork; wire-cell ``+`` is a crossing/turn; arithmetic ``+``
    is inside an operation box. Final outputs have declared-order anchors.

    Plain-body import preserves visible scalar computation, parameters and
    secrecy; it does not reconstruct native widths, IDs, rounds, input bundles
    or unused bits. ``SELn`` and ``JOIN`` helpers require local annotations for
    their masks/bundle widths. Annotated reconstruction retains these native
    details and validates every selection against the actually traced stream.
    Pseudocode alone does not recover arbitrary original placement.

    Balanced minimizes rectangular area plus occupied cells. Other preferences
    prioritize actual crossing-cell count, block-row depth or lane width, with
    deterministic ties. These are heuristic choices, not global optimality
    guarantees. ``synthesis_report`` exposes costs and the selected candidate.

    RAISES:

    ``ValueError`` for invalid options/bounds, unsupported projection or a
    fresh exported-body parse that changes native semantics. Current human
    projection supports uniform unary/binary word operations, constants and
    boundary fragments. Unsupported shapes, oversized labels and custom
    moduli require the explicit audit view. Lanes have fixed manual width;
    arbitrary column-spacing and whole-operation border removal are unsupported.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher, to_ascii, from_ascii
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: drawing = to_ascii(ir)
        sage: from_ascii(to_ascii(ir, annotations=True)) == ir
        True

    Complete default printouts follow. A left margin prevents the doctest
    parser from interpreting a visible ``>>>`` rotation as a Python prompt::

        sage: print('\n'.join(('| '+line.rstrip()).rstrip() for line in drawing.splitlines()))
        |                                    _______
        |   _______    _______    _______   |       |
        |  |  I1   |  |  I2   |  S  I6   |  (DATA1-2)
        |      |          |          |      |_______|
        |      |          |          |
        |   ___v___       |          |       _______
        |  |       |      |          |      |       |
        |  | >>>7  |      |          |      ( KEY6  )
        |  |_______|      |          |      |_______|
        |      |          |          |
        |   ___v___       |          |       _______
        |  |       |      |          |      |       |
        |  |   +   |<-----o          |      (UNUSED )
        |  |_______|      |          |      |_______|
        |      |          |          |
        |   ___v___       |          |       _______
        |  |       |      |          |      |       |
        |  |   ^   |<-----+----------o      ( I3-5  )
        |  |_______|      |          |      |_______|
        |      |          |          |
        |      |       ___v___       |       _______
        |      |      |       |   ___v___   |       |
        |      |      | <<<2  |  |  OBS  |  ( OBS0  )
        |      |      |_______|             |_______|
        |      |          |
        |      |       ___v___
        |      |      |       |
        |      o----->|   ^   |
        |      |      |_______|
        |      |          |
        |      |          |
        |   ___v___    ___v___
        |  |  OUT  |  |  OUT  |
        |
        |

    Generic F chain with exchanged output anchors::

        sage: from claasp.cipher import Cipher
        sage: c = Cipher('generic_feistel', 'permutation', ['left', 'right'], [int(4), int(4)], int(8))
        sage: c.add_round()
        sage: r = c.add_rotate_component(['right'], [list(range(int(4)))], int(4), int(1))
        sage: f = c.add_not_component([r.id], [list(range(int(4)))], int(4))
        sage: x = c.add_xor_component(['left', f.id], [list(range(int(4)))]*int(2), int(4))
        sage: output = c.add_cipher_output_component(['right', x.id], [list(range(int(4)))]*int(2), int(8))
        sage: print('\n'.join(('| '+line.rstrip()).rstrip() for line in to_ascii(from_cipher(c)).splitlines()))
        |
        |   _______    _______
        |  |  I1   |  |  I2   |
        |      |          |
        |      |          |
        |      |          |
        |      |          |
        |      |          o----------+
        |      |          |          |
        |      |          |          |
        |      |          |       ___v___
        |      |          |      |       |
        |      |          |      | >>>1  |
        |      |          |      |_______|
        |      |          |          |
        |      |          |       ___v___
        |      |          |      |       |
        |      |          |      |   !   |
        |      |          |      |_______|
        |      |          |          |
        |   ___v___       |          |
        |  |       |      |          |
        |  |   ^   |<-----+----------+
        |  |_______|      |
        |      |          |
        |      v          v
        |
        |      <---------->
        |
        |      |          |
        |      |          |
        |   ___v___    ___v___
        |  |  OUT  |  |  OUT  |
        |
        |
    """
    if format not in ('human', 'audit'):
        raise ValueError("format must be 'human' or 'audit'")
    bounds = {'max_cells': max_cells, 'max_calls': max_calls,
              'max_grid_area': max_grid_area, 'max_text_bytes': max_text_bytes}
    if any(type(value) is not int or value < 1 for value in bounds.values()):
        raise ValueError('Work and output bounds must be positive integers')
    if format == 'audit':
        if annotations or word_bits is not None or operator_style != 'symbols' or wire_borders or alignment != 'left' or layout_preference != 'balanced':
            raise ValueError('Human rendering/layout options do not apply to the audit format')
        return to_audit_ascii(ir, strategy=strategy, **bounds)
    if not isinstance(ir, dict):
        ir = from_cipher(ir)
    from .manual_blocks import encode
    return encode(ir, annotations=annotations, word_bits=word_bits,
                  operator_style=operator_style, wire_borders=wire_borders,
                  alignment=alignment, layout_preference=layout_preference,
                  strategy=strategy, **bounds)


def synthesis_report(ir, *, word_bits=None, strategy='semantic-auto',
                     alignment='left', layout_preference='balanced',
                     max_cells=1000000, max_calls=20000):
    r"""
    Report measured costs and the selected generic human layout.

    INPUT:

    - ``ir`` -- **dictionary** or **Cipher**; native graph
    - remaining keyword defaults match ``to_ascii`` synthesis controls

    OUTPUT:

    A **dictionary** containing ``selected_variant``, ``metrics`` (crossings,
    depth in block rows, width in lanes, occupied cells), candidate costs and
    the applied alignment/preference. No original dependency graph is stored.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import synthesis_report
        sage: report = synthesis_report(SpeckBlockCipher(number_of_rounds=int(1)))
        sage: sorted(report['metrics'])
        ['cells', 'crossings', 'depth', 'width']
        sage: report['layout_preference']
        'balanced'
    """
    if not isinstance(ir, dict):
        ir = from_cipher(ir)
    from .manual_blocks import build
    _, report = build(ir, word_bits=word_bits, strategy=strategy,
                      alignment=alignment, layout_preference=layout_preference,
                      max_cells=max_cells, max_calls=max_calls)
    return report


def to_audit_ascii(ir, *, strategy='semantic-auto', max_cells=1000000, max_calls=20000,
             max_grid_area=2000000, max_text_bytes=64000000):
    r"""
    Synthesize an editable typed ASCII circuit and verify its visible-wire round trip.

    Manual reference diagrams and primitive names do not participate in synthesis. Bounds reject work rather than omit components.

    INPUT:

    - ``ir`` -- **dictionary** or **Cipher**; complete supported computation
    - ``strategy`` -- **string** (default: ``'semantic-auto'``); deterministic choice among legacy, local-port, independent-parallel and round candidates; explicit values are ``semantic-legacy``, ``semantic-ports``, ``semantic-parallel``, ``semantic-round`` and ``direct-bus``
    - ``max_cells`` -- **integer** (default: ``1000000``); occupied-cell bound
    - ``max_calls`` -- **integer** (default: ``20000``); native/helper-call bound
    - ``max_grid_area`` -- **integer** (default: ``2000000``); full rectangular cell bound
    - ``max_text_bytes`` -- **integer** (default: ``64000000``); UTF-8 output bound

    OUTPUT:

    A **string** containing visible 5-by-11 glyph cells and local definitions. Incoming sources are recovered from wires, not copied into the footer.

    RAISES:

    ``ValueError`` for invalid strategy, exceeded bounds or an exported diagram that fails exact semantic reconstruction.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_audit_ascii
        sage: drawing = to_audit_ascii(ir)
        sage: print('\n'.join(line.rstrip() for line in drawing.splitlines()[1:5]))
          _______    _______
         |  I1   |  S  I2   |
             |          |
             |          |
        sage: local_ports = to_audit_ascii(ir, strategy='semantic-ports')
        sage: local_ports.splitlines()[0].strip()
        ''
    """
    from claasp.cipher_modules.diagram.glyphs import encode, decode
    if not isinstance(ir, dict): ir=from_cipher(ir)
    validate(ir)
    text=encode(ir,strategy=strategy,max_cells=max_cells,max_calls=max_calls,
                max_grid_area=max_grid_area,max_text_bytes=max_text_bytes)
    if validate(decode(text,max_grid_area=max_grid_area,max_text_bytes=max_text_bytes))!=ir: raise ValueError('Native glyph round trip changed semantics')
    return text


def from_ascii(text, *, max_text_bytes=64000000, max_grid_area=2000000):
    r"""
    Parse a typed ASCII drawing by tracing its actual directed ports and bit streams.

    Unannotated legacy art cannot supply missing native tables/widths. Ambiguous, malformed, hidden-dependency and circular routes fail explicitly.

    Annotated manual blocks with ``# CLAASP-HUMAN-BLOCKS 1`` are also
    accepted. Their local native definitions attach to actual readable glyphs;
    fresh routing determines all source links. A plain manual body has no
    native widths/rounds and remains a scalar builder import, not lossless
    native reconstruction through this function.

    INPUT:

    - ``text`` -- **string**; exported typed glyph drawing, or explicit diagnostic record exchange
    - ``max_text_bytes`` -- **integer** (default: ``64000000``); UTF-8 input bound
    - ``max_grid_area`` -- **integer** (default: ``2000000``); rectangle/record bound

    OUTPUT:

    A validated typed **dictionary** with ordered operands and local operation descriptions.

    RAISES:

    ``ValueError`` for malformed framing/routing, ambiguity, incompatible local definitions or exceeded work bounds.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_audit_ascii, from_ascii
        sage: parsed = from_ascii(to_audit_ascii(ir))
        sage: (parsed['name'], parsed['rounds'], parsed['nodes'][0]['description'])
        ('speck', 1, ['ROTATE', 7])
        sage: parsed['nodes'][0]['operands'][0]['source']
        'plaintext'
        sage: parsed['nodes'][0]['operands'][0]['positions']
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    """
    if not isinstance(text,str) or any(type(v) is not int or v<=0 for v in (max_text_bytes,max_grid_area)):
        raise ValueError('Invalid diagram input or work bounds')
    if len(text.encode('utf8'))>max_text_bytes:raise ValueError('Diagram text exceeds max_text_bytes')
    if text.startswith(RECORD_HEADER):
        ir=from_records(text)
        if len(ir['inputs'])+len(ir['nodes'])>max_grid_area:raise ValueError('Record elements exceed max_grid_area')
        return ir
    from .manual_blocks import MARKER as human_marker, decode as decode_human
    if human_marker in text:
        return validate(decode_human(text, max_grid_area=max_grid_area,
                                     max_text_bytes=max_text_bytes))
    from claasp.cipher_modules.diagram.glyphs import decode
    return validate(decode(text,max_text_bytes=max_text_bytes,max_grid_area=max_grid_area))


def to_tikz(ir, **options):
    r"""
    Produce a readable vector overview/detail of the verified native computation.

    Every export reparses its generated ASCII before presentation. Member/input-fragment/parameter tables retain all native operations and tags. ``audit=True`` adds complete local JSON; ``legend='none'`` omits member tables. ``anchorPrefix`` must be unique alphanumeric/hyphen text when combining diagrams.

    Wire options: ``rowsPerPanel=16``, ``columnsPerPanel=6``, ``maxPanels=256``, positive ``columnSpacing=3``/``rowSpacing=1``, and half-open ``rowRange``/``columnRange`` crops. Table options: ``tableLineBudget=42`` fixed 11-point baselines and ``maxPages=2048``; ``overviewStagesPerPanel=6`` limits summaries. ``pageBreaks=False`` lets the caller manage page separation. Crops affect wires, not the complete semantic tables.

    INPUT:

    - ``ir`` -- **dictionary** or **Cipher**; supported computation
    - ``options`` -- **keyword options**; ``view`` selects ``overview-detail`` (default), ``overview``, ``detail`` or ``wires``; ``stageMode`` chooses generic ``round`` or ``layer`` summaries; ``strategy`` chooses the ASCII planner

    OUTPUT:

    A **string** inserted into a LaTeX document body with ``tikz``. Load ``hyperref`` for navigation; fallback commands work without it.

    RAISES:

    ``ValueError`` for invalid presentation options, unsupported semantics or exceeded panel/page bounds.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import to_tikz
        sage: overview = to_tikz(ir, view='overview', stageMode='layer')
        sage: print(next(line for line in overview.splitlines() if 'Computation overview:' in line))
        \par\noindent\textbf{Computation overview: 7 native operations}
        sage: details = to_tikz(ir, view='detail')
        sage: print(next(line for line in details.splitlines() if 'Round 0:' in line))
        \hypertarget{diagram-round-0}{}\par\noindent\textbf{Round 0: 7 native operations (1/1)}
        sage: wires = to_tikz(ir, view='wires', legend='none')
        sage: print(next(line for line in wires.splitlines() if 'begin{tikzpicture}' in line))
        \begin{tikzpicture}[>=stealth]
    """
    from claasp.cipher_modules.diagram.glyphs import _encode_layout, _present_grid, decode
    if not isinstance(ir, dict): ir=from_cipher(ir)
    validate(ir)
    text, cells, dimensions = _encode_layout(ir, strategy=options.get('strategy', 'semantic-auto'))
    recovered = validate(decode(text))
    if recovered != ir:
        raise ValueError('Vector source glyphs changed native IR')
    return _present_grid(recovered, cells, dimensions, options)

def evaluate_state_values(cipher, inputs):
    r"""
    Evaluate native component values keyed by their original source identities.

    INPUT:

    - ``cipher`` -- **Cipher**; original or reconstructed primitive
    - ``inputs`` -- **list of integers**; ordered values fitting the declared input widths

    OUTPUT:

    A **dictionary** of input/component integer values. Reconstructed ciphers use their source-ID mapping; no cipher-specific state adapter is used.

    RAISES:

    ``ValueError`` if the native evaluator does not expose component traces.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.diagrams import from_cipher
        sage: speck = SpeckBlockCipher(number_of_rounds=int(1))
        sage: ir = from_cipher(speck)
        sage: from claasp.diagrams import evaluate_state_values
        sage: values = evaluate_state_values(speck, list(map(int, [0x6574694c, 0x1918111009080100])))
        sage: hex(values['cipher_output_0_6'])
        '0x5316f627'
    """
    evaluated = cipher.evaluate(inputs, intermediate_output=True)
    if not isinstance(evaluated, tuple) or len(evaluated) != 3:
        raise ValueError('Native evaluator did not expose component traces')
    native={**dict(zip(cipher.inputs, inputs)), **{identity: pair[1] for identity,pair in evaluated[2].items()}}
    links=getattr(cipher, 'diagram_source_ids', None)
    return {original:native[generated] for original,generated in links.items()} if links else native


def state_snapshots(ir, *, mode='declared', word_bits=1, columns=None, order='source', values=None, comparison=None):
    r"""
    Build declared observations or generic live-value cuts by round/dependency layer.

    A frontier comprises values with future uses, not a guessed AES/Speck/etc. matrix. Bit selections are MSB-first. The example explicitly supplies a word grouping.

    INPUT:

    - ``ir`` -- **dictionary**; supported graph
    - ``mode`` -- **string** (default: ``'declared'``); ``declared``, ``round`` or ``layer``
    - ``word_bits`` -- **integer** (default: ``1``); explicit group width dividing every selected state
    - ``columns`` -- **integer** (default: ``None``); explicit display columns, not inferred algorithmic geometry
    - ``order`` -- **string** (default: ``'source'``); ``source`` or ``reverse`` source-bit order
    - ``values`` -- **dictionary** (default: ``None``); evaluated values from ``evaluate_state_values``; absent values stay unknown
    - ``comparison`` -- **dictionary** (default: ``None``); second evaluated values; words show XOR differences when both dictionaries are supplied

    OUTPUT:

    A **list of dictionaries** with word positions, values/differences/activity and explicit or ambiguous geometry.

    RAISES:

    ``ValueError`` for invalid modes, shape/order parameters, indivisible words or missing/out-of-range values.

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: width = int(4)
        sage: small = Cipher('small_example', 'permutation', ['data', 'key'], [width, width], width)
        sage: small.add_round()
        sage: xor = small.add_xor_component(['data', 'key'], [list(range(width))]*2, width)
        sage: observation = small.add_intermediate_output_component([xor.id], [list(range(width))], width, 'state')
        sage: small.add_round()
        sage: rotation = small.add_rotate_component([xor.id], [list(range(width))], width, int(-1))
        sage: result = small.add_cipher_output_component([rotation.id], [list(range(width))], width)
        sage: from claasp.diagrams import from_cipher, evaluate_state_values
        sage: ir = from_cipher(small)
        sage: values = evaluate_state_values(small, list(map(int, [9, 3])))
        sage: from claasp.diagrams import state_snapshots
        sage: [[word['value'] for word in frame['words']] for frame in state_snapshots(ir, word_bits=width, values=values)]
        [[10], [5]]
        sage: [[word['value'] for word in frame['words']] for frame in state_snapshots(ir, mode='round', word_bits=width, values=values)]
        [[9, 3], [10], [5]]
        sage: [[word['value'] for word in frame['words']] for frame in state_snapshots(ir, mode='layer', word_bits=width, values=values)]
        [[9, 3], [10], [5], [5]]
    """
    return diagram_states.snapshots(ir, mode=mode, word_bits=word_bits, columns=columns,
                                   order=order, values=values, comparison=comparison)


def state_ascii(ir, **options):
    r"""
    Render generic state snapshots as hex words or explicit unknown cells.

    INPUT:

    - ``ir`` -- **dictionary**; supported graph
    - ``options`` -- **keyword options**; the same mode, word grouping, columns, order and value/comparison dictionaries as ``state_snapshots``

    OUTPUT:

    A **string** of state frames. ``*`` marks a nonzero value or XOR difference.

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: width = int(4)
        sage: small = Cipher('small_example', 'permutation', ['data', 'key'], [width, width], width)
        sage: small.add_round()
        sage: xor = small.add_xor_component(['data', 'key'], [list(range(width))]*2, width)
        sage: observation = small.add_intermediate_output_component([xor.id], [list(range(width))], width, 'state')
        sage: small.add_round()
        sage: rotation = small.add_rotate_component([xor.id], [list(range(width))], width, int(-1))
        sage: result = small.add_cipher_output_component([rotation.id], [list(range(width))], width)
        sage: from claasp.diagrams import from_cipher, evaluate_state_values
        sage: ir = from_cipher(small)
        sage: values = evaluate_state_values(small, list(map(int, [9, 3])))
        sage: from claasp.diagrams import state_ascii
        sage: text = state_ascii(ir, word_bits=width, columns=int(1), values=values)
        sage: print('\n'.join(text.splitlines()[:4]))
        intermediate_output_0_1 (declared, explicit-columns, order=source, word_bits=4)
        +-----+
        |  a* |
        +-----+
        sage: other = evaluate_state_values(small, list(map(int, [8, 3])))
        sage: print(state_ascii(ir, word_bits=width, columns=int(1), values=values, comparison=other).splitlines()[2])
        |  1* |
    """
    return diagram_states.ascii_states(ir, **options)


def state_tikz(ir, *, cell_width=1, cell_height=.5, rows_per_panel=24,
               columns_per_panel=12, frame_range=None, page_breaks=True,
               max_panels=256, row_gap=.25, **options):
    r"""
    Render paginated generic state cells with separate index-label lanes.

    INPUT:

    - ``ir`` -- **dictionary**; supported graph
    - ``cell_width`` -- **number** (default: ``1``); cell width in cm
    - ``cell_height`` -- **number** (default: ``0.5``); value-box height in cm
    - ``rows_per_panel`` -- **integer** (default: ``24``); maximum visible rows per panel
    - ``columns_per_panel`` -- **integer** (default: ``12``); maximum visible columns per panel
    - ``frame_range`` -- **pair of integers** (default: ``None``); explicit half-open snapshot range
    - ``page_breaks`` -- **boolean** (default: ``True``); separate panels on pages
    - ``max_panels`` -- **integer** (default: ``256``); reject rather than truncate excessive output
    - ``row_gap`` -- **number** (default: ``0.25``); reserved index-label lane in cm, at least ``0.25``
    - ``options`` -- **keyword options**; state selection/value options from ``state_snapshots``

    OUTPUT:

    A **string** of TikZ pictures, retaining original cell indices across panels. Insert it in the document body, not in one float.

    RAISES:

    ``ValueError`` for invalid spacing/ranges, incompatible states or excessive panels.

    EXAMPLES::

        sage: from claasp.cipher import Cipher
        sage: width = int(4)
        sage: small = Cipher('small_example', 'permutation', ['data', 'key'], [width, width], width)
        sage: small.add_round()
        sage: xor = small.add_xor_component(['data', 'key'], [list(range(width))]*2, width)
        sage: observation = small.add_intermediate_output_component([xor.id], [list(range(width))], width, 'state')
        sage: small.add_round()
        sage: rotation = small.add_rotate_component([xor.id], [list(range(width))], width, int(-1))
        sage: result = small.add_cipher_output_component([rotation.id], [list(range(width))], width)
        sage: from claasp.diagrams import from_cipher, evaluate_state_values
        sage: ir = from_cipher(small)
        sage: values = evaluate_state_values(small, list(map(int, [9, 3])))
        sage: from claasp.diagrams import state_tikz
        sage: picture = state_tikz(ir, word_bits=width, columns=int(1), values=values)
        sage: print(picture.splitlines()[0])
        \begin{tikzpicture}[font=\scriptsize]
        sage: print(next(line for line in picture.splitlines() if 'fill=orange' in line))
        \node[draw,fill=orange!25,minimum width=1cm,minimum height=0.5cm] at (0,0.0) {a};
    """
    return diagram_states.tikz_states(ir, cell_width=cell_width, cell_height=cell_height,
                                     rows_per_panel=rows_per_panel, columns_per_panel=columns_per_panel,
                                     frame_range=frame_range, page_breaks=page_breaks,
                                     max_panels=max_panels, row_gap=row_gap, **options)
