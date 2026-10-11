// Turns catalog block instances into the exact 5-row-per-block ASCII grammar
// documented in asciiart/notes.md. Every block type renders itself in
// isolation (its own ports/params fully determine its glyphs) -- nothing here
// looks at neighboring grid cells. See webapp/tools/verify-blocks.mjs for the
// byte-for-byte check against asciiart/manual_examples/blocks/**.
import { operandOrder, BLOCK_TYPES, blockWords, blockPorts, blockRowSpan, resolve, resolveLabel, resolveMultiblockPermutation, multiblockPermutationEdges, packEdgesIntoRows, permutationLayout, resolveActiveWords, resolveSwapActiveWords } from './blockCatalog.js';

export const ROW_HEIGHT = 5;
export const WORD_WIDTH = 11;

function padLabel(label, interiorWidth) {
  const clamped = label.slice(0, interiorWidth); // a 'free' or long symbol label can't be allowed to overrun the box frame
  const left = Math.floor((interiorWidth - clamped.length) / 2);
  const right = interiorWidth - clamped.length - left;
  return ' '.repeat(Math.max(left, 0)) + clamped + ' '.repeat(Math.max(right, 0));
}

// `active` is either a plain boolean (every word the same, the common case)
// or a per-word predicate `(wordIndex) => boolean` -- used by renderIo so a
// spacer word (see blockCatalog.js's ACTIVE_WORDS_PARAM) can leave its own
// centre column blank while its neighbors still show their connector.
function isWordActive(active, i) {
  return typeof active === 'function' ? active(i) : active;
}

// Row of underscores spanning the block, with a connector glyph (or nothing)
// punched in at each word's local centre column (11*i + 5), and the two
// leftmost/rightmost columns left blank. Used for the top row of every
// family (component, wiring, and IO's top-border row alike) -- all share
// the same 'v' top-connector glyph.
function borderRowWithConnectors(width, words, glyph, active) {
  const chars = new Array(width).fill('_');
  chars[0] = ' ';
  chars[1] = ' ';
  chars[width - 2] = ' ';
  chars[width - 1] = ' ';
  for (let i = 0; i < words; i++) {
    const centre = WORD_WIDTH * i + 5;
    if (isWordActive(active, i)) chars[centre] = glyph;
  }
  return chars.join('');
}

// Plain underscore border, single frame, no per-word breaks: "|_______|".
// Used for component bottom rows and IO's bottom-border row. `leftChar`
// overrides the left frame character (default '|') -- used by renderIo to
// draw a secret input's 'S' marker in that exact position without touching
// any other call site.
function plainBorderRow(width, leftChar = '|') {
  const chars = new Array(width).fill('_');
  chars[0] = ' ';
  chars[width - 1] = ' ';
  chars[1] = leftChar;
  chars[width - 2] = '|';
  return chars.join('');
}

// Same border row, but with an id centered into the underscore run between
// the two pipe characters (see renderIo's own comment for why this is the
// only line an IO block has room to put text in without reshaping the box).
function plainBorderRowWithId(width, leftChar, id) {
  const row = plainBorderRow(width, leftChar);
  return row.slice(0, 2) + padLabel(id, width - 4) + row.slice(width - 2);
}

// Blank row with a glyph (default '|') at each word's local centre where
// `active` is true. Used for component bottom-pipe row and IO's
// approach/continuation rows -- and, with an explicit '^' glyph, a wiring
// block's borderless bottom row when that port is an input (see
// renderWiring) rather than the usual output.
function pipeRow(width, words, active, glyph = '|') {
  const chars = new Array(width).fill(' ');
  for (let i = 0; i < words; i++) {
    if (isWordActive(active, i)) chars[WORD_WIDTH * i + 5] = glyph;
  }
  return chars.join('');
}

function blankRow(width) {
  return ' '.repeat(width);
}

function renderComponent(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  const words = blockWords(typeName, params);
  const width = words * WORD_WIDTH;
  const ports = blockPorts(typeName, params, 0, words);
  const topActive = words > 1
    ? (i) => blockPorts(typeName, params, i, words).top === 'in'
    : ports.top === 'in';
  // Bottom is 'out' for every pre-existing catalog type, but a rotated
  // component (see blockCatalog.js's rotateParams) can also give it 'in' --
  // the pipe row (l4) is drawn either way, but only l3's border glyph below
  // needs to actually distinguish the two (a plain '|' pipe row reads fine
  // regardless of direction, matching the existing top-side convention where
  // only the border row, not the interior pipe, carries the arrow).
  const bottomActive = words > 1
    ? (i) => Boolean(blockPorts(typeName, params, i, words).bottom)
    : Boolean(ports.bottom);
  const label = resolveLabel(typeName, params);
  const labelWidth = width - 4;
  if (typeName === 'free_text' && label.length > labelWidth) throw new Error(`Function label exceeds visible capacity (${labelWidth}); use a wider explicit box or typed DAG.`);
  const continuedConstant = typeName === 'constant' && params.operator_style === 'symbol' && label.length > labelWidth;
  if (continuedConstant && label.length > 2 * labelWidth) {
    throw new Error(`Constant needs ${label.length} label characters, but this box supports ${2 * labelWidth}; use a wider explicitly typed representation.`);
  }
  const shape = resolve(type.shape, params);
  // Which single side (if any) should visually taper to indicate a
  // bit-width change -- the tapered end represents the smaller-width side,
  // e.g. 'bottom' for a many-to-one op (xor/and/or/sbox[surjective]: the
  // combined inputs are "wider" than the single output), or 'left'/'right'
  // for a component rotated to run inline in a horizontal chain, tapering
  // toward whichever single side is actually the narrow one (see
  // blockCatalog.js's own `narrow` field for the full rationale, including
  // the reversed case -- an *expanding* op tapers toward its input side
  // instead). Only meaningful for a single-word component, same scope as
  // the left/right/top/bottom port overrides.
  const narrow = words === 1 ? resolve(type.narrow, params) || 'none' : 'none';

  const l0 = (() => {
    if (words > 1) return borderRowWithConnectors(width, words, 'v', topActive); // one connector per word, narrow never applies here
    const chars = new Array(width).fill('_');
    chars[0] = ' ';
    chars[1] = ' ';
    chars[width - 2] = ' ';
    chars[width - 1] = ' ';
    if (narrow === 'left') chars[2] = ' ';
    if (narrow === 'right') chars[width - 3] = ' ';
    if (topActive) chars[5] = 'v';
    return chars.join('');
  })();

  const l1 = (() => {
    const chars = new Array(width).fill(' ');
    chars[1] = narrow === 'left' ? ' ' : '|';
    chars[width - 2] = narrow === 'right' ? ' ' : '|';
    if (narrow === 'left') chars[2] = '/';
    if (narrow === 'right') chars[width - 3] = '\\';
    if (params.operand_order) {
      if (!['xor','and','or','typedbox'].includes(typeName) || words !== 1) throw new Error('Operand binding supports scalar gates and typed operations only');
      operandOrder(params,Object.values(ports).filter(v=>v==='in').length);
      const text = padLabel('@'+params.operand_order,labelWidth);
      for (let i=0;i<text.length;i++) chars[2+i]=text[i];
    }
    if (continuedConstant) {
      const text = padLabel(label.slice(0, labelWidth), labelWidth);
      for (let i = 0; i < text.length; i++) chars[2 + i] = text[i];
    }
    return chars.join('');
  })();

  const l2 = (() => {
    const chars = new Array(width).fill(' ');
    const leftFrame = shape === 'bracket' ? '[' : shape === 'typed' ? '(' : '|';
    const rightFrame = shape === 'bracket' ? ']' : shape === 'typed' ? ')' : '|';
    chars[1] = leftFrame;
    chars[width - 2] = rightFrame;
    if (words === 1) {
      if (ports.left) chars[0] = glyphFor(ports.left, 'left');
      if (ports.right) chars[width - 1] = glyphFor(ports.right, 'right');
    }
    const interior = width - 4;
    const displayedLabel = continuedConstant
      ? label.slice(interior) : label;
    const padded = padLabel(displayedLabel, interior);
    for (let i = 0; i < padded.length; i++) chars[2 + i] = padded[i];
    return chars.join('');
  })();

  const l3 = (() => {
    if (narrow === 'bottom') return '  \\' + '_'.repeat(width - 6) + '/  ';
    const chars = new Array(width).fill('_');
    chars[0] = ' ';
    chars[width - 1] = ' ';
    chars[1] = narrow === 'left' ? ' ' : '|';
    chars[width - 2] = narrow === 'right' ? ' ' : '|';
    if (narrow === 'left') chars[2] = '\\';
    if (narrow === 'right') chars[width - 3] = '/';
    // The border itself always stays a clean, unbroken shape regardless of
    // port direction -- bottom='in' is signalled one row down instead, on
    // the approach pipe (l4), the same way an 'in' vs 'out' distinction on
    // left/right only ever shows up on the block's own edge column, never
    // punched into the border run.
    return chars.join('');
  })();

  // Multi-word components always keep their bottom output active (no
  // per-word override exists there, see blockCatalog.js's blockPorts) --
  // only a single-word component's bottom can be turned off, which
  // bottomActive (from the same blockPorts call) already reflects. '^'
  // marks an 'in' (only reachable via a rotated component, see
  // blockCatalog.js's rotateParams); the pre-existing 'out' keeps its
  // plain '|'.
  const l4 = pipeRow(width, words, bottomActive, ports.bottom === 'in' ? '^' : '|');

  return [l0, l1, l2, l3, l4];
}

function glyphFor(direction, side) {
  if (direction === 'in') return side === 'left' ? '>' : '<';
  return '-'; // outgoing
}

function renderWiring(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  const ports = resolve(type.ports, params);
  const junction = resolve(type.junction, params);
  const visible = params.borders === 'visible';
  const width = WORD_WIDTH;

  const topActive = ports.top === 'in';
  const bottomActive = Boolean(ports.bottom); // 'out' (the default) or, since rotateParams, 'in'
  const bottomGlyph = ports.bottom === 'in' ? '^' : '|';
  const leftActive = Boolean(ports.left);
  const rightActive = Boolean(ports.right);
  const hasVertical = topActive || bottomActive;
  const hasHorizontal = leftActive || rightActive;

  const l0 = visible
    ? borderRowWithConnectors(width, 1, 'v', topActive)
    : pipeRow(width, 1, topActive);

  const l1 = (() => {
    const chars = new Array(width).fill(' ');
    if (visible) {
      chars[1] = '|';
      chars[width - 2] = '|';
    }
    if (topActive) chars[5] = '|';
    return chars.join('');
  })();

  const l2 = (() => {
    const chars = new Array(width).fill(' ');
    if (visible) {
      chars[1] = '|';
      chars[width - 2] = '|';
    }
    if (hasVertical && !hasHorizontal) {
      chars[5] = '|';
    } else if (hasHorizontal && !hasVertical) {
      const start = visible ? 2 : 0;
      const end = visible ? 8 : 10;
      for (let i = start; i <= end; i++) chars[i] = '-';
      if (leftActive) chars[0] = visible ? glyphFor(ports.left, 'left') : '-';
      if (rightActive) chars[width - 1] = visible ? glyphFor(ports.right, 'right') : '-';
    } else {
      if (leftActive) {
        for (let i = visible ? 2 : 0; i < 5; i++) chars[i] = '-';
        chars[0] = visible ? glyphFor(ports.left, 'left') : '-';
      }
      if (rightActive) {
        for (let i = 6; i <= (visible ? 8 : 10); i++) chars[i] = '-';
        chars[width - 1] = visible ? glyphFor(ports.right, 'right') : '-';
      }
      chars[5] = junction;
    }
    return chars.join('');
  })();

  // Invisible mode drops all box-drawing characters, leaving just a plain
  // pipe (like L4) if the bottom port is active. Either way, l3 itself never
  // shows the in/out distinction -- same "border stays clean, the approach
  // pipe one row down carries it" rule as renderComponent's l3/l4.
  const l3 = visible
    ? (() => {
        const chars = new Array(width).fill('_');
        chars[0] = ' ';
        chars[width - 1] = ' ';
        chars[1] = '|';
        chars[width - 2] = '|';
        if (bottomActive) chars[5] = '|';
        return chars.join('');
      })()
    : pipeRow(width, 1, bottomActive);

  const l4 = pipeRow(width, 1, bottomActive, bottomGlyph);

  return [l0, l1, l2, l3, l4];
}

function renderIoSingleWord(kind, showId, id) {
  const topActive = kind !== 'input';
  const bottomActive = kind !== 'output';
  return [
    pipeRow(WORD_WIDTH, 1, topActive),
    borderRowWithConnectors(WORD_WIDTH, 1, 'v', topActive),
    showId ? plainBorderRowWithId(WORD_WIDTH, '|', id) : plainBorderRow(WORD_WIDTH),
    pipeRow(WORD_WIDTH, 1, bottomActive),
    pipeRow(WORD_WIDTH, 1, bottomActive),
  ];
}

// An IO block's own box (see asciiart/notes.md) has no interior content
// line of its own -- unlike a component, which always has one for its
// label -- so when `showId` is on (see renderGrid's own option, never
// persisted) the id is centered into the border row's own underscore run,
// between its two pipe characters (see plainBorderRowWithId), rather than
// on a separate line -- a preview-only overlay, not a connectivity change
// (checkConnectivity reads the port model directly, never this text).
function renderIo(typeName, params, showId) {
  const type = BLOCK_TYPES[typeName];
  const words = params.words;
  const merged = type.kind === 'output' ? params.merged !== false : true;
  const id = params.id || '';

  if (!merged && words > 1) {
    const parts = new Array(ROW_HEIGHT).fill('');
    for (let i = 0; i < words; i++) {
      const single = renderIoSingleWord(type.kind, showId && i === 0, id);
      for (let r = 0; r < ROW_HEIGHT; r++) parts[r] += single[r];
    }
    return parts;
  }

  const width = words * WORD_WIDTH;
  // A spacer word (see blockCatalog.js's ACTIVE_WORDS_PARAM) has no
  // connector at all, on whichever side this kind would otherwise show one
  // -- the frame itself (plainBorderRow) stays one continuous box either way.
  const activeWords = resolveActiveWords(params, words);
  const isActive = (i) => activeWords.includes(i);
  const topActive = (i) => type.kind !== 'input' && isActive(i);
  const bottomActive = (i) => type.kind !== 'output' && isActive(i);
  const leftChar = type.kind === 'input' && params.secrecy === 'secret' ? 'S' : '|';
  return [
    pipeRow(width, words, topActive),
    borderRowWithConnectors(width, words, 'v', topActive),
    showId ? plainBorderRowWithId(width, leftChar, id) : plainBorderRow(width, leftChar),
    pipeRow(width, words, bottomActive),
    pipeRow(width, words, bottomActive),
  ];
}

// Literal 5x11 templates for double_wire's two *turning* variants only --
// see blockCatalog.js's double_wire comment for why this doesn't go through
// renderWiring's generic junction logic: two overlaid turns need a diagonal
// offset instead of a single shared centre point, which is a genuinely
// different shape (one glyph can't carry which two sides pair up for two
// independent bends the way it can for two straight lines). top_to_right+
// left_to_bottom is this same drawing mirrored left-to-right (columns
// reflected, '/' <-> '\').
const DOUBLE_WIRE_TEMPLATES = {
  'top_to_left+right_to_bottom': ['     |     ', '    /      ', '---/   /---', '      /    ', '     |     '],
  'top_to_right+left_to_bottom': ['     |     ', '      \\    ', '---\\   \\---', '    \\      ', '     |     '],
};

// double_wire's two *straight-through* variants (formerly `cross`) need no
// template at all -- they're exactly what renderWiring's generic ports/
// junction engine already draws for any block with both an active vertical
// and an active horizontal pair (see its own comment): the shared '+'
// dropped at the fixed centre column. Only the turning variants above need
// the literal diagonal drawing.
function renderDoubleWire(typeName, params) {
  const template = DOUBLE_WIRE_TEMPLATES[params.variant];
  return template ? [...template] : renderWiring(typeName, params);
}

// Borderless: each of the 2 active words' own top-in/bottom-out pipe passes
// through unbroken, but the two values trade columns at the middle row via
// mirrored arrows at each active word's own centre (not its edge -- unlike
// every other directional glyph in this grammar, which only ever appears at
// a block's left/right edge). Any word outside the active pair (see
// blockCatalog.js's resolveSwapActiveWords) is a pure spacer -- blank on
// every row, same as an inactive io word. See
// asciiart/manual_examples/toy_primitives/swap_permutation.
function renderSwap(params) {
  const words = blockWords('swap', params);
  const width = words * WORD_WIDTH;
  const [a, b] = resolveSwapActiveWords(params, words);
  const isActive = (i) => i === a || i === b;
  const centre = (i) => WORD_WIDTH * i + 5;

  const crossingRow = (() => {
    const chars = new Array(width).fill(' ');
    for (let c = centre(a); c <= centre(b); c++) chars[c] = '-';
    chars[centre(a)] = '<';
    chars[centre(b)] = '>';
    return chars.join('');
  })();

  const approach = pipeRow(width, words, isActive);
  return [approach, approach, crossingRow, approach, approach];
}

// Row with `glyph` punched at a sparse *subset* of word indices, rather
// than "every word 0..words-1" like pipeRow -- multiblockpermutation's
// v-row/pipe-row only punch the glyph at activeInputs/activeOutputs, which
// (with independent gaps) aren't always "every word" or even the same set
// as each other. `underscored` draws the border-row style (visible mode);
// otherwise a blank background.
function rowWithGlyphsAt(width, activeIndices, glyph, underscored) {
  const chars = new Array(width).fill(underscored ? '_' : ' ');
  if (underscored) {
    chars[0] = ' ';
    chars[1] = ' ';
    chars[width - 2] = ' ';
    chars[width - 1] = ' ';
  }
  for (const i of activeIndices) chars[WORD_WIDTH * i + 5] = glyph;
  return chars.join('');
}

// One content row's worth of swap-lines/directional lines -- see
// blockCatalog.js's permutationEdges/packEdgesIntoRows for how a
// permutation is decomposed and packed into rows in the first place.
function renderPermutationContentRow(width, edges) {
  const chars = new Array(width).fill(' ');
  const centre = (i) => WORD_WIDTH * i + 5;
  for (const edge of edges) {
    if (edge.type === 'swap') {
      const lo = Math.min(edge.a, edge.b);
      const hi = Math.max(edge.a, edge.b);
      for (let c = centre(lo); c <= centre(hi); c++) chars[c] = '-';
      chars[centre(lo)] = '<';
      chars[centre(hi)] = '>';
    } else {
      const lo = Math.min(edge.src, edge.dst);
      const hi = Math.max(edge.src, edge.dst);
      for (let c = centre(lo); c <= centre(hi); c++) chars[c] = '-';
      chars[centre(edge.src)] = 'o';
      chars[centre(edge.dst)] = edge.dst < edge.src ? '<' : '>';
    }
  }
  return chars.join('');
}

// Variable-height: the v-row and pipe-row are always exactly 1 line each,
// but everything between them is however many content rows the resolved
// edges need (see packEdgesIntoRows) plus symmetric blank padding (any odd
// remainder goes to the top) so the total is a multiple of ROW_HEIGHT --
// matching blockCatalog.js's blockRowSpan, which grid.js uses to reserve the
// right number of grid rows before this ever runs.
//
// activeInputs/activeOutputs (see resolveMultiblockPermutation) needn't be
// "every word" or even the same set as each other -- the v-row only punches
// a connector at activeInputs, the pipe-row only at activeOutputs, and any
// word in neither is a pure spacer (see "Partial input/output connectors"
// in notes.md).
function renderMultiBlockPermutation(params) {
  const resolved = resolveMultiblockPermutation(params);
  const { words, activeInputs, activeOutputs, permutation } = resolved;
  const width = words * WORD_WIDTH;
  const visible = params.borders === 'visible';

  const contentLines = packEdgesIntoRows(multiblockPermutationEdges(activeInputs, activeOutputs, permutation)).map((edges) => renderPermutationContentRow(width, edges));
  const { topPad, bottomPad } = permutationLayout(resolved, params.borders);

  const framed = (line) => {
    if (!visible) return line;
    const chars = line.split('');
    chars[1] = '|';
    chars[width - 2] = '|';
    return chars.join('');
  };

  const blank = blankRow(width);
  const l0 = rowWithGlyphsAt(width, activeInputs, 'v', visible);
  const middleLines = [...Array(topPad).fill(blank), ...contentLines, ...Array(bottomPad).fill(blank)].map(framed);
  // Bordered mode closes its box one row above the diagram's actual bottom
  // connectors: the border row and the pipe row are two separate final
  // lines, never fused -- see blockCatalog.js's permutationLayout.
  const tailLines = visible ? [plainBorderRow(width), rowWithGlyphsAt(width, activeOutputs, '|', false)] : [rowWithGlyphsAt(width, activeOutputs, '|', false)];

  return [l0, ...middleLines, ...tailLines];
}

// Returns the block's 5 text rows (each `wordsWide(block)*11` chars).
// `showId`, only ever passed by renderGrid's own preview-only option
// (see there), forces a component to display its id in place of its
// normal word/symbol/free label, and an IO block to show its id on its
// approach-pipe line -- without touching `params.operator_style` itself,
// so a block's own persisted display choice survives toggling this on
// and off. Wiring-family blocks (wire/split/double_wire/swap/
// multiblockpermutation) don't get this treatment --
// their glyphs (junctions, diagonal turns) have no spare room for
// arbitrary text -- they still carry a real `id` (for uniqueness and any
// future metadata listing), it just isn't shown inline.
export function renderBlock(typeName, params, showId = false) {
  const type = BLOCK_TYPES[typeName];
  if (type.family === 'component') return renderComponent(typeName, showId ? { ...params, operator_style: 'id' } : params);
  if (type.family === 'wiring') return renderWiring(typeName, params);
  if (type.family === 'io') return renderIo(typeName, params, showId);
  if (type.family === 'double_wire') return renderDoubleWire(typeName, params);
  if (type.family === 'swap') return renderSwap(params);
  if (type.family === 'multiblockpermutation') return renderMultiBlockPermutation(params);
  throw new Error(`Unknown block family for type "${typeName}"`);
}

// ---------------------------------------------------------------- routes --
// Most block types have exactly one meaningful signal: every active input
// combines into the single output (even a multi-input xor -- the output
// genuinely depends on ALL of its inputs together, so there's nothing to
// split). But a handful of wiring-ish types draw two or more *independent*
// paths through the same box that never actually connect to each other --
// `double_wire`'s two routes, whether both straight (vertical top<->bottom
// and horizontal left<->right -- visually cross but don't mix) or both
// turning (a diagonal-offset overlay of two single-turn routes); `swap`'s
// two words are independent pass-throughs (the crossing is purely visual --
// see its own catalog comment);
// `multiblockpermutation` is k independent input->output pairs. Taint
// tracing (connectivity.js's computeSecretTaint) needs to follow each of
// these separately, and the Preview/grid diagram view need to color only
// the specific characters belonging to a tainted route -- not the whole
// block -- so a mixed-secrecy block reads correctly instead of either
// over- or under-highlighting.
//
// blockRoutes(typeName, params) returns { routes, height, width }, where
// each route is { into: [{side, wordOffset}], outs: [{side, wordOffset}],
// cells: [[line, col], ...] }. `cells` lists exactly the characters (within
// the block's own local line/column coordinates) that belong to that route
// and nothing else -- a shared/ambiguous glyph (e.g. double_wire's straight-
// through '+' junction, or a mutual swap-line shared by both directions of
// an exchange) is deliberately left out of every route's cells rather than
// guessed at.
//
// Default (everything not special-cased below): a single route covering
// every active port and the block's entire rendered area, matching the
// original whole-block taint model -- exact for any block with only one
// real signal path (which is every 'component', 'io', 'split', 'wire'
// instance; multi-word components like mixcolumn are treated as a single
// all-words-mix route too, since the catalog doesn't encode a more precise
// internal word-to-word mapping for those).
function buildRouteResult(routes, height, width) {
  return { routes, height, width };
}

function defaultRoutes(typeName, params) {
  const words = blockWords(typeName, params);
  const height = blockRowSpan(typeName, params) * ROW_HEIGHT;
  const width = words * WORD_WIDTH;
  const into = [];
  const out = [];
  for (let w = 0; w < words; w++) {
    const ports = blockPorts(typeName, params, w, words);
    for (const side of ['top', 'left', 'right', 'bottom']) {
      if (ports[side] === 'in') into.push({ side, wordOffset: w });
      if (ports[side] === 'out') out.push({ side, wordOffset: w });
    }
  }
  const cells = [];
  for (let line = 0; line < height; line++) for (let col = 0; col < width; col++) cells.push([line, col]);
  // A single route with (possibly) several inputs/outputs -- computeSecretTaint
  // treats a route's own taint as "every one of its `into` sources is
  // tainted," so a multi-input default route still gets the original
  // whole-block AND semantics.
  return buildRouteResult([{ into, outs: out, cells }], height, width);
}

// double_wire's straight-through variants (formerly `cross`): vertical
// (top<->bottom) and horizontal (left<->right, or right<->left) never mix --
// verified against the actual renderWiring output for all border/variant
// combinations. The '+' junction (always at line 2, col 5 when both are
// active, which these variants always have) is shared and excluded from
// both. The horizontal direction is read directly off `variant` (whichever
// half isn't 'top_to_bottom') instead of a separate `mirrored` param.
function straightDoubleWireRoutes(params) {
  const visible = params.borders === 'visible';
  const horizontalKey = params.variant.split('+').find((key) => key !== 'top_to_bottom');
  const [hEntry, hExit] = horizontalKey.split('_to_');
  const vertical = {
    into: [{ side: 'top', wordOffset: 0 }],
    outs: [{ side: 'bottom', wordOffset: 0 }],
    cells: [
      [0, 5],
      [1, 5],
      [3, 5],
      [4, 5],
    ],
  };
  const leftCols = visible ? [0, 2, 3, 4] : [0, 1, 2, 3, 4];
  const rightCols = visible ? [6, 7, 8, 10] : [6, 7, 8, 9, 10];
  const horizontalCells = [...leftCols, ...rightCols].map((c) => [2, c]);
  const horizontal = { into: [{ side: hEntry, wordOffset: 0 }], outs: [{ side: hExit, wordOffset: 0 }], cells: horizontalCells };
  return buildRouteResult([vertical, horizontal], ROW_HEIGHT, WORD_WIDTH);
}

// double_wire's turning variants (formerly `double_rewire`): two single-turn
// routes overlaid with a deliberate diagonal offset specifically so they
// never share a character (see its catalog comment) -- positions verified
// directly against DOUBLE_WIRE_TEMPLATES.
const DOUBLE_WIRE_ROUTE_CELLS = {
  'top_to_left+right_to_bottom': {
    a: { into: 'top', out: 'left', cells: [[0, 5], [1, 4], [2, 0], [2, 1], [2, 2], [2, 3]] },
    b: { into: 'right', out: 'bottom', cells: [[2, 7], [2, 8], [2, 9], [2, 10], [3, 6], [4, 5]] },
  },
  'top_to_right+left_to_bottom': {
    a: { into: 'top', out: 'right', cells: [[0, 5], [1, 6], [2, 7], [2, 8], [2, 9], [2, 10]] },
    b: { into: 'left', out: 'bottom', cells: [[2, 0], [2, 1], [2, 2], [2, 3], [3, 4], [4, 5]] },
  },
};

function doubleWireRoutes(params) {
  const turning = DOUBLE_WIRE_ROUTE_CELLS[params.variant];
  if (!turning) return straightDoubleWireRoutes(params);
  const toRoute = (r) => ({ into: [{ side: r.into, wordOffset: 0 }], outs: [{ side: r.out, wordOffset: 0 }], cells: r.cells });
  return buildRouteResult([toRoute(turning.a), toRoute(turning.b)], ROW_HEIGHT, WORD_WIDTH);
}

// swap: per asciiart/notes.md's own swap-line semantics (a `<---------->`
// line is always a *mutual* exchange), the value entering at word `a`'s top
// exits at word `b`'s bottom and vice versa -- a real crossing, not two
// independent top-in/bottom-out passes. The crossing row itself (line 2) is
// shared by both routes and stays uncoloured, same treatment as
// double_wire's shared junction. A spacer word (outside the active pair) has
// no port at all, so it contributes no route.
function swapRoutes(params) {
  const words = blockWords('swap', params);
  const width = words * WORD_WIDTH;
  const [a, b] = resolveSwapActiveWords(params, words);
  const centre = (i) => WORD_WIDTH * i + 5;
  const routeFor = (enterWord, exitWord) => ({
    into: [{ side: 'top', wordOffset: enterWord }],
    outs: [{ side: 'bottom', wordOffset: exitWord }],
    cells: [
      [0, centre(enterWord)],
      [1, centre(enterWord)],
      [3, centre(exitWord)],
      [4, centre(exitWord)],
    ],
  });
  return buildRouteResult([routeFor(a, b), routeFor(b, a)], ROW_HEIGHT, width);
}

// multiblockpermutation: activeInputs[i] always flows to
// activeOutputs[permutation[i]], whether or not a line is actually drawn
// for it (a same-column mapping is silently implied -- see notes.md's
// "Partial input/output connectors"), so the *logical* route list is built
// straight from the resolved permutation, independent of drawing. Each
// route's v-row/pipe-row glyphs are always attributable to it alone. A
// drawn directional edge's content-row dashes belong to its one route; a
// mutual swap-line is shared by both directions of that exchange and is
// left uncolored, same reasoning as double_wire's shared junction.
function multiBlockPermutationRoutes(params) {
  const resolved = resolveMultiblockPermutation(params);
  const { activeInputs, activeOutputs, permutation } = resolved;
  const width = resolved.words * WORD_WIDTH;
  const layout = permutationLayout(resolved, params.borders);
  const height = layout.rowSpan * ROW_HEIGHT;
  const centre = (i) => WORD_WIDTH * i + 5;

  const k = permutation.length;
  const routes = permutation.map((destIndex, i) => ({
    into: [{ side: 'top', wordOffset: activeInputs[i] }],
    outs: [{ side: 'bottom', wordOffset: activeOutputs[destIndex] }],
    cells: [
      [0, centre(activeInputs[i])],
      [height - 1, centre(activeOutputs[destIndex])],
    ],
  }));
  const routeByInputCol = new Map(activeInputs.map((col, i) => [col, i]));

  const rows = packEdgesIntoRows(multiblockPermutationEdges(activeInputs, activeOutputs, permutation));
  const contentStartLine = 1 + layout.topPad; // line 0 is the v-row
  rows.forEach((rowEdges, rowIdx) => {
    const line = contentStartLine + rowIdx;
    for (const edge of rowEdges) {
      if (edge.type !== 'edge') continue; // 'swap' edges are shared -- deliberately uncolored
      const routeIndex = routeByInputCol.get(edge.src);
      const lo = Math.min(edge.src, edge.dst);
      const hi = Math.max(edge.src, edge.dst);
      for (let c = centre(lo); c <= centre(hi); c++) routes[routeIndex].cells.push([line, c]);
    }
  });

  return buildRouteResult(routes, height, width);
}

// See the file-header comment above buildRouteResult for the full contract.
export function blockRoutes(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  if (type.family === 'double_wire') return doubleWireRoutes(params);
  if (type.family === 'swap') return swapRoutes(params);
  if (type.family === 'multiblockpermutation') return multiBlockPermutationRoutes(params);
  return defaultRoutes(typeName, params);
}

// Renders a full grid (see grid.js) to the final multi-line ASCII string.
// Gaps between/around placed blocks are filled with blank word-cells so every
// row stays aligned. Blocks normally span exactly one grid row (rowSpan 1,
// ROW_HEIGHT=5 lines), but a decoded/raw multi-row block (see decode.js)
// reserves several grid rows and contributes a different 5-line slice of its
// own pre-rendered text to each one it spans.
// `options.showIds` (default false, never persisted -- purely a Preview-
// panel toggle, see app.js) overlays every block's own id in place of its
// normal content, without touching the grid's actual stored params -- see
// renderBlock's own comment for exactly what that means per block family.
export function renderGrid(grid, options = {}) {
  const { showIds = false } = options;
  const { rows, cols } = grid.dimensions();
  const lineCache = new Map(); // block -> its full rendered lines (rowSpan*5 of them)
  const fullLines = (block) => {
    if (!lineCache.has(block)) {
      lineCache.set(block, block.raw ? block.lines : renderBlock(block.type, block.params, showIds));
    }
    return lineCache.get(block);
  };

  const outputLines = [];
  for (let r = 0; r < rows; r++) {
    for (let i = 0; i < ROW_HEIGHT; i++) {
      let line = '';
      let c = 0;
      while (c < cols) {
        const block = grid.getBlockAt(r, c);
        if (block && block.col === c) {
          line += fullLines(block)[(r - block.row) * ROW_HEIGHT + i];
          c += block.words;
        } else {
          line += blankRow(WORD_WIDTH);
          c += 1;
        }
      }
      outputLines.push(line);
    }
  }
  return outputLines.join('\n');
}
