// Data-only description of every block type this app knows how to draw.
// The exact character grammar this encodes is documented in asciiart/notes.md
// and validated byte-for-byte against asciiart/manual_examples/blocks/** (see
// webapp/tools/verify-blocks.mjs).

// ---- cryptographic components (family: "component") ----------------------
// `inputs` controls which side ports exist: 0 -> none, 1 -> top only,
// 2 -> top+left, 3 -> top+left+right. `words` controls how many word-slots
// (11-char units) the block spans; multi-word components always have inputs=1
// (one top port per word) and use a longer label centered across the whole
// merged interior.
//
// Every component has two label representations -- `label` (the "word"
// style, e.g. "XOR") and `symbol` (the "symbol" style, e.g. "^"; see
// asciiart/operator_symbols.txt for the full mapping and rationale) -- plus
// `operator_style` ('word' | 'symbol' | 'free') selects between them, with
// 'free' using the instance's own `free_text` instead of either. Both
// `label` and `symbol` may be functions of params (e.g. rotate's symbol
// embeds its direction+amount); see resolveLabel().
const STYLE_PARAMS = [
  { name: 'operator_style', options: ['word', 'symbol', 'free', 'id'], default: 'word' },
  { name: 'free_text', kind: 'text', default: '' },
];

// Every block instance's own stable identifier -- distinct from `label`
// (a free-text *grouping* tag, purely editor-session metadata) and from
// `operator_style`'s display choice above: `id` is the thing itself
// being named, not how it's drawn. Blank means "not explicitly set" --
// Grid.placeBlock (grid.js) fills in a real value the moment a block is
// actually placed (see defaultIdFor below), so by the time any code
// reads a placed block's `params.id`, it's always populated; pseudocode
// synthesis (pseudocodeLayout.js) sets it explicitly to the pseudocode-
// given name instead of letting that default apply. Spread into every
// single block type via the loop right after BLOCK_TYPES below (not
// per-family, since identity genuinely applies to every block, including
// `input`, which pointedly gets no `label`).
const ID_PARAM = [{ name: 'id', kind: 'text', default: '' }];

// Two-letter type abbreviation used by defaultIdFor's fallback id
// (abbreviation + row + col, e.g. "SB0_0", "MC10_2", "RO2_111" -- chosen
// so the common case stays at or under 9 characters, matching a
// single-word block's own interior width). Every BLOCK_TYPES key must
// have an entry here (checked by verify-blocks.mjs) and every entry must
// be unique.
export const TYPE_ABBREV = {
  sbox: 'SB', xor: 'XO', and: 'AN', or: 'OR', not: 'NT',
  modadd: 'MA', modsub: 'MS', modmul: 'MM', ideamodmul: 'IM',
  rotate: 'RO', shift: 'SH', variablerotate: 'VR', variableshift: 'VS',
  permutation: 'PM', reverse: 'RV', sigma: 'SI', constant: 'CN', free_text: 'FT', typedbox: 'TB',
  linearlayer: 'LL', mixcolumn: 'MC', wordpermutation: 'WP', shiftrows: 'SR',
  thetakeccak: 'TK', thetaxoodoo: 'TX', thetagaston: 'TG',
  input: 'IN', output: 'OU', intermediate_output: 'IO',
  split: 'SP', wire: 'WR',
  double_wire: 'DW', swap: 'SW', multiblockpermutation: 'MP',
};

// The id a freshly-placed block gets when nothing else supplied one --
// "the block name plus its coordinates" (as opposed to a pseudocode-
// synthesized block, which gets the pseudocode-given name set directly
// as an explicit `id` instead, bypassing this fallback entirely).
// Coordinates alone already guarantee uniqueness (two blocks can't
// occupy the same cell), so this default never collides with another
// default -- only an explicit, user-edited id needs a uniqueness check
// (see Grid.isIdTaken in grid.js).
export function defaultIdFor(typeName, row, col) {
  const abbrev = TYPE_ABBREV[typeName] || typeName.slice(0, 2).toUpperCase();
  return `${abbrev}${row}_${col}`;
}

// Free-text group tag, purely editor-session metadata (never drawn, never
// part of a .asciiart file) used to highlight related blocks (e.g. the
// blocks belonging to one round of a cipher) with a shared background color
// -- see the label-colors panel in app.js. Spread alongside STYLE_PARAMS at
// every family's param declaration except `input` -- it alone keeps an
// implicit identity instead (see its own `secrecy` param below), since it's
// an opaque external source rather than a real step in the dataflow.
const LABEL_PARAM = [{ name: 'label', kind: 'text', default: 'round' }];

// A block width is an open-ended positive integer. Keeping this as a number
// input (instead of enumerating a few convenient widths) lets every block
// that spans word slots grow to the width its diagram actually needs.
const wordsParam = (defaultWords = 1, min = 1) => ({
  name: 'words', kind: 'number', min, step: 1, default: defaultWords,
});

const component = (label, inputs, symbol, extra = {}) => ({
  family: 'component',
  category: 'cryptographic_components',
  label,
  symbol,
  inputs,
  words: (params) => params.words ?? 1,
  shape: 'box',
  params: [wordsParam(), ...STYLE_PARAMS, ...LABEL_PARAM],
  ...extra,
});

const multiWordComponent = (label, symbol, defaultWords, minWords = 1) => ({
  family: 'component',
  category: 'cryptographic_components',
  label,
  symbol,
  inputs: 1,
  shape: 'box',
  params: [wordsParam(defaultWords, minWords), ...STYLE_PARAMS, ...LABEL_PARAM],
  words: (params) => params.words,
});

// ---- IO blocks (family: "io") ----------------------------------------------
// A comma-separated, strictly-increasing list of word indices (0..words-1)
// that have a real port -- any word NOT listed is pure spacer width (no
// connector glyph, nothing expected above/below it), mirroring
// multiblockpermutation's own activeInputs/activeOutputs (see
// parseWordIndexList and resolveMultiblockPermutation's comments). Blank
// (the default) means "every word", reducing exactly to the pre-existing
// no-gaps behavior. Useful for drawing a construction where two values have
// different bit-widths (e.g. an unbalanced Feistel's two halves): the wider
// one's extra word(s) can be shown as blank width alongside the narrower
// one, without needing every word to carry an independently-wired value.
const ACTIVE_WORDS_PARAM = { name: 'activeWords', kind: 'text', default: '' };
const ACTIVE_INPUTS_PARAM = { name: 'activeInputs', kind: 'text', default: '' };
const ACTIVE_OUTPUTS_PARAM = { name: 'activeOutputs', kind: 'text', default: '' };

const io = (kind, extra = {}) => ({
  family: 'io',
  category: 'io',
  kind,
  params: [wordsParam()],
  ...extra,
});

// ---- wiring blocks (family: "wiring") --------------------------------------
// `ports` maps side -> 'in' | 'out' | undefined (absent). `junction` is the
// glyph drawn at the block's centre when more than a straight pass-through is
// happening: 'o' duplicates a value (split), '+' redirects/crosses it.
const wiring = (extra) => ({
  family: 'wiring',
  category: 'wiring',
  params: [{ name: 'borders', options: ['visible', 'invisible'], default: 'invisible' }, ...LABEL_PARAM],
  ...extra,
});

export const REWIRE_PORTS = {
  // A plain straight pass-through (formerly its own separate `identity`
  // type) -- folded in here since it's exactly "a wire from top to bottom",
  // same as every other entry names its own two sides.
  top_to_bottom: { top: 'in', bottom: 'out' },
  top_to_left: { top: 'in', left: 'out' },
  top_to_right: { top: 'in', right: 'out' },
  left_to_right: { left: 'in', right: 'out' },
  right_to_left: { right: 'in', left: 'out' },
  left_to_bottom: { left: 'in', bottom: 'out' },
  right_to_bottom: { right: 'in', bottom: 'out' },
  // No bottom_to_left/bottom_to_right: bottom is never an in-port anywhere
  // in this catalog (matches componentSidePort's own rule -- a value is
  // never received from below, only ever produced downward), so a value
  // "arriving from below" isn't a real direction, just an upside-down
  // drawing of left_to_bottom/right_to_bottom.
};

// One in-port, two or three out-ports -- see `split`'s own params comment
// for why every combination is spelled out here instead of composed from
// independent toggles.
const SPLIT_PORTS = {
  top_to_left_and_bottom: { top: 'in', left: 'out', bottom: 'out' },
  top_to_right_and_bottom: { top: 'in', right: 'out', bottom: 'out' },
  left_to_right_and_bottom: { left: 'in', right: 'out', bottom: 'out' },
  right_to_left_and_bottom: { right: 'in', left: 'out', bottom: 'out' },
  top_to_left_and_right: { top: 'in', left: 'out', right: 'out' },
  top_to_left_and_right_and_bottom: { top: 'in', left: 'out', right: 'out', bottom: 'out' },
};

// Any operation that folds multiple inputs into one output (xor/and/or/
// modular ops, sbox[surjective]) can optionally show that visually: a
// tapered border on the single narrow (smaller-width) side -- see
// render.js's renderComponent for the actual geometry, and its own comment
// for why the taper can point either way (a *contracting* op like these
// narrows toward its output; an *expanding* op, only expressible today via
// free_text's own explicit `narrow` param, narrows toward its input
// instead). Shared by every component below that's inherently many-to-one;
// sbox keeps its own `type` param instead since bijective/surjective is
// already the natural name for that choice there.
const SURJECTIVE_PARAM = { name: 'surjective', options: [false, true], default: false };
// Bottom is where the output normally lives, but rotateParams (below) can
// move it to left/right instead -- taper whichever single side is actually
// the sole 'out' port right now rather than hardcoding 'bottom', so a
// rotated surjective component's taper stays aligned with its real output
// instead of silently pointing the wrong way.
const narrowTowardOutput = (typeName) => (p) => {
  if (!p.surjective) return 'none';
  const outSides = ['left', 'right', 'bottom'].filter((side) => componentSidePort(typeName, p, side) === 'out');
  return outSides.length === 1 ? outSides[0] : 'bottom';
};

export const BLOCK_TYPES = {
  // -- cryptographic components --
  sbox: {
    ...component('SBOX', 1, 'S'),
    params: [wordsParam(), { name: 'type', options: ['bijective', 'surjective'], default: 'bijective' }, ...STYLE_PARAMS, ...LABEL_PARAM],
    narrow: (params) => narrowTowardOutput('sbox')({ ...params, surjective: params.type === 'surjective' }),
  },
  // `side` only matters when inputs=2: a 2-input op's second connector can
  // arrive from the left (the common case) or the right (seen e.g. in
  // toy_primitives/even_mansour_*'s key XOR). Ignored when inputs=3 (both
  // sides are used then).
  xor: {
    ...component('XOR', 2, '^'),
    params: [
      wordsParam(),
      { name: 'inputs', options: [2, 3], default: 2 },
      { name: 'side', options: ['left', 'right'], default: 'left' },
      ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM,
    ],
    inputs: (p) => p.inputs,
    narrow: narrowTowardOutput('xor'),
  },
  and: {
    ...component('AND', 2, '&'),
    params: [
      wordsParam(),
      { name: 'inputs', options: [2, 3], default: 2 },
      { name: 'side', options: ['left', 'right'], default: 'left' },
      ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM,
    ],
    inputs: (p) => p.inputs,
    narrow: narrowTowardOutput('and'),
  },
  or: {
    ...component('OR', 2, '|'),
    params: [
      wordsParam(),
      { name: 'inputs', options: [2, 3], default: 2 },
      { name: 'side', options: ['left', 'right'], default: 'left' },
      ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM,
    ],
    inputs: (p) => p.inputs,
    narrow: narrowTowardOutput('or'),
  },
  not: component('NOT', 1, '!'),
  modadd: { ...component('MODA', 2, '+'), params: [wordsParam(), ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM], narrow: narrowTowardOutput('modadd') },
  modsub: { ...component('MODS', 2, '-'), params: [wordsParam(), ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM], narrow: narrowTowardOutput('modsub') },
  modmul: { ...component('MODM', 2, '*'), params: [wordsParam(), ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM], narrow: narrowTowardOutput('modmul') },
  ideamodmul: { ...component('IMODM', 2, 'x'), params: [wordsParam(), ...STYLE_PARAMS, ...LABEL_PARAM, SURJECTIVE_PARAM], narrow: narrowTowardOutput('ideamodmul') },
  // Symbol style embeds the actual direction+amount, e.g. ">>>19"/"<<<7"
  // (rotate) or ">>19"/"<<7" (shift, one fewer arrow so it's visually
  // distinguishable from rotate) -- see asciiart/manual_examples/primitives/ascon.
  // `words` lets a rotate/shift span several word-slots merged into one box
  // (e.g. AES combining 4 bytes into a word before rotating it -- see
  // asciiart/manual_examples/primitives/aes), the same multi-word merge
  // multiWordComponent's own types (mixcolumn, shiftrows, ...) use, just
  // with the amount/direction-driven dynamic label kept instead of a fixed
  // one. Defaults to 1, so every pre-existing single-word example is
  // unaffected.
  rotate: {
    ...component('ROT', 1, (p) => `${p.direction === 'left' ? '<<<' : '>>>'}${p.amount}`),
    params: [
      { name: 'direction', options: ['left', 'right'], default: 'right' },
      { name: 'amount', kind: 'number', default: 1 },
      wordsParam(),
      ...STYLE_PARAMS, ...LABEL_PARAM,
    ],
    words: (p) => p.words ?? 1,
  },
  shift: {
    ...component('SHIFT', 1, (p) => `${p.direction === 'left' ? '<<' : '>>'}${p.amount}`),
    params: [
      { name: 'direction', options: ['left', 'right'], default: 'right' },
      { name: 'amount', kind: 'number', default: 1 },
      wordsParam(),
      ...STYLE_PARAMS, ...LABEL_PARAM,
    ],
    words: (p) => p.words ?? 1,
  },
  // No amount here -- the shift/rotate distance is itself a second wire
  // input for these two, not a fixed param, so there's no static value to
  // embed; the symbol shows just the direction.
  variablerotate: {
    ...component('VROT', 2, (p) => (p.direction === 'left' ? '<<<' : '>>>')),
    params: [wordsParam(), { name: 'direction', options: ['left', 'right'], default: 'right' }, ...STYLE_PARAMS, ...LABEL_PARAM],
  },
  variableshift: {
    ...component('VSHFT', 2, (p) => (p.direction === 'left' ? '<<' : '>>')),
    params: [wordsParam(), { name: 'direction', options: ['left', 'right'], default: 'right' }, ...STYLE_PARAMS, ...LABEL_PARAM],
  },
  permutation: component('PERM', 1, 'P'),
  reverse: component('REV', 1, '<->'),
  sigma: component('SIGMA', 1, 'SIG'),
  // Symbol style embeds the constant's own hex value, e.g. "x4B" -- see
  // asciiart/manual_examples/primitives/ascon/ascon[rounds=1,operator_style=symbol].asciiart.
  constant: {
    ...component('CONST', 0, (p) => `x${p.value}`),
    params: [wordsParam(), { name: 'value', kind: 'text', default: '00' }, ...STYLE_PARAMS, ...LABEL_PARAM],
  },
  // A box holding arbitrary user text (e.g. a generic round function "F", a
  // custom operator like "A^B") instead of a fixed catalog word -- unlike
  // an existing component's operator_style='free' (xor/and/.../sbox's own
  // free_text override, see STYLE_PARAMS above), which is fundamentally
  // ambiguous to decode back (many types render an *identical* frame once
  // the one thing that would tell them apart -- the label -- is arbitrary
  // text), this is its own dedicated type: its `[`/`]` frame (shape:
  // 'bracket', see render.js's renderComponent) is a signal no other type
  // ever produces, so decode.js can recognize it unambiguously (see its
  // tryFreeTextMatch). Interior width for one word is 7 characters
  // (WORD_WIDTH=11 minus the 2 frame chars and 2 port-glyph columns) --
  // text longer than that is silently clamped by render.js's padLabel,
  // same as any other over-long label.
  free_text: {
    family: 'component',
    category: 'cryptographic_components',
    label: (p) => p.text || '',
    inputs: 1,
    words: (params) => params.words ?? 1,
    shape: 'bracket',
    // Unlike the other components above, free_text has no fixed
    // mathematical operation to infer a taper direction from -- it's a
    // stand-in for anything, contracting or expanding -- so its narrow
    // side is an explicit, independent choice rather than derived from
    // in/out state.
    params: [
      wordsParam(),
      { name: 'text', kind: 'text', default: 'F', maxLength: 7 },
      { name: 'narrow', options: ['none', 'bottom', 'left', 'right'], default: 'none' },
      ...LABEL_PARAM,
    ],
    narrow: (p) => p.narrow || 'none',
  },
  linearlayer: component('LINL', 1, 'L'),
  mixcolumn: {
    ...multiWordComponent('MIXCOLUMN', 'MC', 4),
    label: (p) => (p.words === 1 ? 'MIXC' : 'MIXCOLUMN'),
  },
  wordpermutation: multiWordComponent('WORDPERM', 'WP', 4),
  shiftrows: multiWordComponent('SHIFTROWS', 'SR', 4),
  thetakeccak: multiWordComponent('THETAKECCAK', 'THK', 3),
  thetaxoodoo: multiWordComponent('THETAXOODOO', 'THX', 3),
  thetagaston: multiWordComponent('THETAGASTON', 'THG', 3),

  // -- IO --
  // `secrecy` is always stored, but only ever visibly changes the render
  // when 'secret' -- 'public' renders identically to a bare `words` param
  // (the classic, pre-existing signature), so every existing example stays
  // valid and decodes as secrecy:'public'. A secret input always draws its
  // 'S' marker (see render.js's renderIo) so the marking can't be silently
  // lost by hiding it -- there's no equivalent "invisible secret" form.
  input: io('input', {
    params: [
      wordsParam(),
      { name: 'secrecy', options: ['public', 'secret'], default: 'public' },
      { name: 'source_index', kind: 'text', default: '' },
      ACTIVE_WORDS_PARAM,
    ],
  }),
  output: io('output', {
    params: [
      wordsParam(),
      { name: 'merged', options: [true, false], default: true },
      // Pseudocode synthesis may place an output on its inferred state lane,
      // so its visual left-to-right label is deliberately independent from
      // the assignment name used when converting the grid back to code.
      { name: 'semanticName', kind: 'text', default: '', internal: true },
      ...LABEL_PARAM,
      ACTIVE_WORDS_PARAM,
    ],
  }),
  // Unlike input, output/intermediate_output can be labeled like any other
  // non-input block -- they're a real step in a diagram's dataflow (a round
  // boundary, an exposed intermediate value), not an opaque external source.
  intermediate_output: io('intermediate_output', {
    params: [wordsParam(), ...LABEL_PARAM, ACTIVE_WORDS_PARAM],
  }),

  // -- wiring --
  // A single route connecting one in-port to one out-port -- `direction`
  // names which side is which (e.g. 'top_to_left'), reusing REWIRE_PORTS as
  // the one source of truth for every direction, including the plain
  // straight-through pass ('top_to_bottom', formerly its own separate
  // `identity` type -- it's exactly "a wire from top to bottom", nothing
  // else distinguishes it, so it doesn't need its own catalog entry).
  wire: wiring({
    params: [
      { name: 'direction', options: Object.keys(REWIRE_PORTS), default: 'top_to_bottom' },
      { name: 'borders', options: ['visible', 'invisible'], default: 'invisible' },
      ...LABEL_PARAM,
    ],
    junction: (p) => (['top_to_bottom', 'left_to_right', 'right_to_left'].includes(p.direction) ? null : '+'),
    ports: (p) => ({ ...REWIRE_PORTS[p.direction] }),
  }),
  // Two independent routes through one cell, each named the same way a
  // plain `wire` names its own direction, joined with '+'. `variant` is any
  // pairing of two REWIRE_PORTS keys that together use all 4 sides exactly
  // once (one route starts at top, the other ends at bottom) -- which
  // leaves exactly 4 geometrically sensible combinations: both routes
  // straight through (vertical top<->bottom + horizontal left<->right, in
  // either horizontal direction -- this is what used to be its own `cross`
  // type, `mirrored` folded into which horizontal direction the variant
  // names), or both routes turning (top+left paired with right+bottom, or
  // top+right paired with left+bottom -- drawn from
  // asciiart/manual_examples/blocks/wiring/double_wire/double_wire[...].asciiart).
  // See render.js's renderDoubleWire/doubleWireRoutes for why the turning
  // pair needs a diagonal-offset drawing instead of the straight pair's
  // single shared junction glyph: two overlaid *turns* need their pairing
  // communicated visually (one glyph can't distinguish "top-left+right-
  // bottom" from "top-right+left-bottom"), while two straight lines don't
  // (verticality/horizontality already implies which sides pair up).
  double_wire: {
    family: 'double_wire',
    category: 'wiring',
    params: [
      {
        name: 'variant',
        options: ['top_to_bottom+left_to_right', 'top_to_bottom+right_to_left', 'top_to_left+right_to_bottom', 'top_to_right+left_to_bottom'],
        default: 'top_to_bottom+left_to_right',
      },
      // Only meaningful for the two straight-through variants (drawn via
      // the generic wiring engine, see renderDoubleWire) -- a no-op for the
      // turning variants, whose diagonal-offset drawing has never had a
      // border/borderless distinction.
      { name: 'borders', options: ['visible', 'invisible'], default: 'invisible' },
      ...LABEL_PARAM,
    ],
    junction: '+',
    ports: (p) => p.variant.split('+').reduce((acc, key) => ({ ...acc, ...REWIRE_PORTS[key] }), {}),
  },
  split: wiring({
    params: [
      // Every combination is named the same way a `wire`/`double_wire`
      // names its own direction(s): which side is the single input, and
      // which side(s) -- joined with "_and_" -- are outputs. There is no
      // separate on/off toggle for the bottom output the way there used to
      // be: each combination that's actually meaningful in this catalog's
      // top-down convention gets its own fully-named option instead, so a
      // param that doesn't affect ports can never silently tie two
      // different directions together (confirmed to happen for real: a
      // former `bottom` toggle made a side-only split collide byte-for-byte
      // with a plain `wire`'s horizontal pass-through under invisible
      // borders).
      {
        name: 'direction',
        options: [
          'top_to_left_and_bottom',
          'top_to_right_and_bottom',
          'left_to_right_and_bottom',
          'right_to_left_and_bottom',
          'top_to_left_and_right', // T-junction: both sides, no bottom
          'top_to_left_and_right_and_bottom', // 3-way: both sides and bottom
        ],
        default: 'top_to_right_and_bottom',
      },
      { name: 'borders', options: ['visible', 'invisible'], default: 'invisible' },
      ...LABEL_PARAM,
    ],
    junction: 'o',
    ports: (p) => ({ ...SPLIT_PORTS[p.direction] }),
  }),
  // Exchanges the two words' values: the value entering at word `a`'s top
  // exits at word `b`'s bottom and vice versa -- a real crossing, traced as
  // such by render.js's own swapRoutes (used by pseudocode.js's extraction)
  // even though this table's own per-word `ports` (below, used by
  // connectivity.js's simpler "does each port have a matching neighbor"
  // check) doesn't need to represent the crossing itself, only that each
  // active word has a top-in/bottom-out pair. Borderless by design, matching
  // asciiart/manual_examples/toy_primitives/swap_permutation.
  //
  // `words` is the block's total width (default/min 2 -- a swap needs at
  // least the two words it exchanges); `activeWords` names exactly which 2
  // of them those are (blank means "every word", which is only valid when
  // `words` itself is 2 -- see resolveSwapActiveWords). Any word not in
  // that pair is a pure spacer, no connector at all, same convention as
  // io's own ACTIVE_WORDS_PARAM -- useful for lining the swapped pair up
  // with specific columns in a wider diagram without a third block type.
  // Unlike multiblockpermutation, a swap is always exactly one pair with
  // input/output at the same two columns (never a k-way permutation or
  // repositioned outputs) -- that's what multiblockpermutation itself is
  // for; this stays deliberately narrow.
  swap: {
    family: 'swap',
    category: 'wiring',
    // `inputs: 1` doesn't describe swap's own ports (blockPorts handles the
    // `family === 'swap'` case directly, see below, independent of this
    // field) -- it exists purely so pseudocode.js's isMultiWordType()
    // recognizes a synthetic 2-argument swap call (placement.js's
    // detectSwapPairs) as a Mode C group call, letting wiring.js's existing
    // placeGroupCall place and wire it with no further special-casing.
    inputs: 1,
    params: [wordsParam(2, 2), ACTIVE_WORDS_PARAM, ...LABEL_PARAM],
  },
  // An arbitrary permutation of k active input/output pairs, expressed with
  // swap-lines ("<---------->", mutual exchange) and directional lines
  // ("o----------->"/"<-----------o", one-way, source marked 'o') -- see
  // the "Multi-block permutations" section of asciiart/notes.md. `permutation`
  // is a comma-separated list (e.g. "2,0,1" -- active input i's value exits
  // at active output perm[i]).
  //
  // `words` is the block's total width in word-slots (may exceed
  // permutation.length -- a word with neither an input nor an output is a
  // pure spacer). `activeInputs`/`activeOutputs` are each a comma-separated,
  // strictly-increasing list of word indices (0..words-1) that have a
  // 'v'/'|' connector -- same length as `permutation`, but not necessarily
  // the same *set* as each other (see "Partial input/output connectors" in
  // notes.md). Left blank, each defaults to "every word" (0..words-1), and
  // `words` defaults to permutation.length -- together that reduces exactly
  // to the original no-gaps model.
  //
  // Row-span is variable (always a multiple of 5, computed from how many
  // content rows the resolved edges need -- see permutationLayout).
  multiblockpermutation: {
    family: 'multiblockpermutation',
    category: 'wiring',
    params: [
      { name: 'permutation', kind: 'text', default: '1,0' },
      { name: 'words', kind: 'text', default: '' },
      { name: 'activeInputs', kind: 'text', default: '' },
      { name: 'activeOutputs', kind: 'text', default: '' },
      { name: 'borders', options: ['visible', 'invisible'], default: 'invisible' },
      ...LABEL_PARAM,
    ],
  },
};

// Explicitly typed operation boxes carry a visible alias. Their semantics
// live in per-box annotations; topology always comes from glyph connections.
BLOCK_TYPES.typedbox = {
  ...BLOCK_TYPES.free_text, inputs:p=>Number(p.arity ?? 1), shape:'typed',
  params:[{name:'text',kind:'text',default:'NODE',maxLength:7},{name:'arity',kind:'number',min:0,max:3,default:1},...LABEL_PARAM]
};

// A visible local binding: @21 maps logical operands to physical input
// ports in [left,top,right,bottom] reading order. Default is identity.
for (const name of ['xor','and','or','typedbox']) BLOCK_TYPES[name].params.push({name:'operand_order',kind:'text',default:''});
export function operandOrder(params, count) {
  if (!params.operand_order) return Array.from({length:count},(_,i)=>i);
  const order = String(params.operand_order).split('').map(n=>Number(n)-1);
  if (order.length !== count || new Set(order).size !== count || order.some(n=>!Number.isInteger(n)||n<0||n>=count)) throw new Error('Operand binding must be a permutation of the visible input ports');
  return order;
}

// Every component can become a merged multi-word block. At that point its
// top inputs and bottom outputs may be enabled independently per word.
// Blank means every word; "none" means no words.
for (const type of Object.values(BLOCK_TYPES)) {
  if (type.family !== 'component') continue;
  if (!type.params.some((p) => p.name === 'activeInputs')) type.params.push(ACTIVE_INPUTS_PARAM);
  if (!type.params.some((p) => p.name === 'activeOutputs')) type.params.push(ACTIVE_OUTPUTS_PARAM);
}

// Every block, of every family (including `input`, which pointedly gets
// no `label`), gets an `id` -- see ID_PARAM's own comment for why this is
// a distinct concept from label/operator_style.
for (const type of Object.values(BLOCK_TYPES)) {
  if (!type.params.some((p) => p.name === 'id')) type.params.push(...ID_PARAM);
}

// Parses a "2,0,1" style permutation string into [2, 0, 1], validating it's
// a genuine bijection on 0..n-1 (n >= 2). Throws a descriptive error
// otherwise -- used both by render.js (which must fail loudly on a
// malformed instance rather than draw something misleading) and by the
// palette/editor UI to validate user-entered text.
export function parsePermutation(text) {
  const parts = String(text).split(',').map((s) => s.trim());
  if (parts.length < 2 || parts.some((s) => !/^\d+$/.test(s))) {
    throw new Error(`Invalid permutation "${text}": expected 2+ comma-separated non-negative integers`);
  }
  const perm = parts.map(Number);
  const n = perm.length;
  const seen = new Array(n).fill(false);
  for (const v of perm) {
    if (v < 0 || v >= n || seen[v]) {
      throw new Error(`Invalid permutation "${text}": not a bijection on 0..${n - 1}`);
    }
    seen[v] = true;
  }
  return perm;
}

// Parses a "0,2,3" style word-index list: strictly increasing, each in
// 0..n-1. Empty string means "unset" (caller substitutes a default, usually
// "every word"). Used for activeInputs/activeOutputs.
export function parseWordIndexList(text, n) {
  if (text === '' || text == null) return null;
  if (String(text).trim().toLowerCase() === 'none') return [];
  const parts = String(text).split(',').map((s) => s.trim());
  if (parts.some((s) => !/^\d+$/.test(s))) {
    throw new Error(`Invalid word index list "${text}": expected comma-separated non-negative integers`);
  }
  const list = parts.map(Number);
  for (let i = 0; i < list.length; i++) {
    if (list[i] < 0 || list[i] >= n) {
      throw new Error(`Invalid word index list "${text}": index ${list[i]} out of range 0..${n - 1}`);
    }
    if (i > 0 && list[i] <= list[i - 1]) {
      throw new Error(`Invalid word index list "${text}": indices must be strictly increasing`);
    }
  }
  return list;
}

// The common "activeWords blank means every word" default -- copy-pasted as
// `parseWordIndexList(params.activeWords, words) ?? Array.from({ length:
// words }, (_, i) => i)` in blockCatalog.js/render.js/pseudocode.js (4x)
// before this helper existed; single-sourced here instead.
export function resolveActiveWords(params, words) {
  return parseWordIndexList(params.activeWords, words) ?? Array.from({ length: words }, (_, i) => i);
}

// Resolves swap's activeWords to exactly the 2 word indices that actually
// exchange values -- blank means "every word" (parseWordIndexList's usual
// default), which is only ever valid when `words` itself is 2 (the
// original, still-default shape); anything else must name the pair
// explicitly. Throws otherwise, same "validate at the point of use, fail
// loudly" convention as parsePermutation/resolveMultiblockPermutation.
export function resolveSwapActiveWords(params, words) {
  const active = resolveActiveWords(params, words);
  if (active.length !== 2) {
    throw new Error(`Invalid activeWords for swap: expected exactly 2 word indices (of ${words}), got ${JSON.stringify(active)}`);
  }
  return active;
}

// Resolves a multiblockpermutation instance's full layout from its raw
// params: the permutation array, total word width, and the two active
// column lists -- applying the "every word, aligned" defaults that make
// this reduce exactly to the original no-gaps model when activeInputs/
// activeOutputs/words are left blank. Throws on any inconsistency (wrong
// list length, index out of range, non-increasing).
export function resolveMultiblockPermutation(params) {
  const permutation = parsePermutation(params.permutation);
  const k = permutation.length;
  const words = params.words ? Number(params.words) : k;
  if (!Number.isInteger(words) || words < k) {
    throw new Error(`Invalid words count for multiblockpermutation: "${params.words}" (must be an integer >= permutation length ${k})`);
  }
  const identity = Array.from({ length: k }, (_, i) => i);
  const activeInputs = parseWordIndexList(params.activeInputs, words) ?? identity;
  const activeOutputs = parseWordIndexList(params.activeOutputs, words) ?? identity;
  if (activeInputs.length !== k) throw new Error(`activeInputs must list exactly ${k} word(s) (one per permutation entry), got ${activeInputs.length}`);
  if (activeOutputs.length !== k) throw new Error(`activeOutputs must list exactly ${k} word(s) (one per permutation entry), got ${activeOutputs.length}`);
  return { words, activeInputs, activeOutputs, permutation };
}

// Decomposes a permutation into its cycles, each as a list of word indices
// in traversal order (e.g. [2,0,1] -> [[0,2,1]]: 0->2->1->0). Fixed points
// (perm[i] === i) are omitted -- they're handled separately by
// multiblockPermutationEdges, since whether they need a line now depends on
// column alignment, not just index equality.
function permutationCycles(perm) {
  const n = perm.length;
  const seen = new Array(n).fill(false);
  const cycles = [];
  for (let i = 0; i < n; i++) {
    if (seen[i] || perm[i] === i) {
      seen[i] = true;
      continue;
    }
    const cycle = [];
    let j = i;
    while (!seen[j]) {
      seen[j] = true;
      cycle.push(j);
      j = perm[j];
    }
    cycles.push(cycle);
  }
  return cycles;
}

// Turns each cycle into swap-lines (length-2 cycles -- one mutual
// swap-line) or directional lines (longer cycles -- one directed edge per
// consecutive pair, wrapping around). Edges are returned in cycle-traversal
// order (cycles in index order, edges within a cycle in traversal order) --
// packEdgesIntoRows relies on this order to match the row layout used
// throughout asciiart/notes.md's examples.
// Word-index pair (not permutation-array index) for a directed edge --
// pushed only if the input and output columns actually differ; a same-
// column mapping is a silent vertical pass-through, drawn as nothing (see
// "Partial input/output connectors" in notes.md).
function pushDirectedOrSkip(edges, inCol, outCol) {
  if (inCol === outCol) return;
  edges.push({ type: 'edge', src: inCol, dst: outCol });
}

// Builds the full set of drawn edges for a multiblockpermutation instance,
// as physical word-index pairs ready for packEdgesIntoRows/rendering.
// `activeInputs[i]`/`activeOutputs[j]` translate the permutation's own
// index space (0..k-1, left-to-right order within each list) to actual
// word columns -- when both lists are the identity (the no-gaps case),
// this reduces exactly to the original word-index-only model.
//
// A swap-line only ever replaces a *mutual* 2-cycle where both members are
// self-aligned (their own input and output sit at the same column) --
// otherwise even a 2-cycle becomes two separate directional lines, since a
// single "<---->" glyph can't express two different pairs of columns.
// Fixed points (perm[i] === i) are handled the same way as any other
// mapping: silent if input/output columns match, a directed line if they
// don't (which can happen once input/output gaps aren't aligned).
export function multiblockPermutationEdges(activeInputs, activeOutputs, perm) {
  const k = perm.length;
  const edges = [];
  for (const cycle of permutationCycles(perm)) {
    if (cycle.length === 2) {
      const [i, j] = cycle;
      const selfAlignedI = activeInputs[i] === activeOutputs[i];
      const selfAlignedJ = activeInputs[j] === activeOutputs[j];
      if (selfAlignedI && selfAlignedJ) {
        edges.push({ type: 'swap', a: activeInputs[i], b: activeInputs[j] });
      } else {
        pushDirectedOrSkip(edges, activeInputs[i], activeOutputs[j]);
        pushDirectedOrSkip(edges, activeInputs[j], activeOutputs[i]);
      }
    } else {
      for (const i of cycle) {
        pushDirectedOrSkip(edges, activeInputs[i], activeOutputs[perm[i]]);
      }
    }
  }
  for (let i = 0; i < k; i++) {
    if (perm[i] === i) pushDirectedOrSkip(edges, activeInputs[i], activeOutputs[i]);
  }
  return edges;
}

function edgeRange(edge) {
  return edge.type === 'swap' ? [Math.min(edge.a, edge.b), Math.max(edge.a, edge.b)] : [Math.min(edge.src, edge.dst), Math.max(edge.src, edge.dst)];
}

// Packs edges into the fewest possible rows such that no two edges sharing
// a row have overlapping (or touching) word-index ranges -- greedy first-fit
// in edges' given order (see permutationEdges for why that order matters).
// Returns an array of rows, each an array of edges assigned to it.
export function packEdgesIntoRows(edges) {
  const rows = []; // each: { edges: [...], lastEnd }
  for (const edge of edges) {
    const [start, end] = edgeRange(edge);
    const row = rows.find((r) => start > r.lastEnd);
    if (row) {
      row.edges.push(edge);
      row.lastEnd = end;
    } else {
      rows.push({ edges: [edge], lastEnd: end });
    }
  }
  return rows.map((r) => r.edges);
}

// Computes the full row layout for a multiblockpermutation instance, shared
// by render.js (renderMultiBlockPermutation) and blockRowSpan below. Takes
// the same { activeInputs, activeOutputs, permutation } shape
// resolveMultiblockPermutation returns.
//
// Bordered mode draws one extra row (the box's own closing border row, just
// above the always-separate bottom pipe row) that borderless doesn't need.
// If `totalLines`/`rowSpan` were computed per-border-mode, toggling borders
// on an already-tightly-packed block (content rows filling every available
// line, zero spare padding) would change its height and truncate it -- but
// every other block type keeps an identical row count regardless of border
// visibility (borders only ever change what's *drawn* in already-reserved
// rows, e.g. a wiring block's row 3 becomes a border-closing line instead
// of a plain continuation pipe -- never an added row). So `totalLines` is
// always computed as if bordered (the larger requirement), even when
// borderless -- borderless just leaves that reserved row as an
// indistinguishable extra blank padding line instead of using it. Content+
// padding fills whatever's left of the *actual* border mode's own fixed-row
// count, and any odd remainder goes to the top pad (both verified against
// asciiart/manual_examples/blocks/wiring/multiblockpermutation/).
export function permutationLayout({ activeInputs, activeOutputs, permutation }, borders) {
  const contentRows = packEdgesIntoRows(multiblockPermutationEdges(activeInputs, activeOutputs, permutation)).length;
  const totalLines = Math.ceil((3 + contentRows) / 5) * 5; // always as if bordered -- see above
  const fixedRows = borders === 'visible' ? 3 : 2;
  const padding = totalLines - fixedRows - contentRows;
  const topPad = Math.ceil(padding / 2);
  const bottomPad = Math.floor(padding / 2);
  return { contentRows, totalLines, topPad, bottomPad, rowSpan: totalLines / 5 };
}

// Every combination of a type's declared param options, e.g. for xor
// ({inputs: [2, 3]}) this yields [{inputs: 2}, {inputs: 3}]. Used by
// decode.js to build the full set of known block "signatures" to match
// raw ASCII text against.
export function allParamCombos(typeName) {
  const type = BLOCK_TYPES[typeName];
  let combos = [{}];
  for (const param of type.params) {
    if (param.kind) continue; // 'text'/'number' params are open-ended (free text, a rotate amount, a
    // constant's value, ...) -- decode.js recognizes these via a dedicated pattern match instead of
    // enumerating every possible value here.
    const next = [];
    for (const combo of combos) {
      for (const option of param.options) next.push({ ...combo, [param.name]: option });
    }
    combos = next;
  }
  return combos;
}

// Resolves a component's actual label text for its current operator_style:
// 'word' (e.g. "XOR", the default -- matches every pre-existing example),
// 'symbol' (e.g. "^", or with an embedded value like ">>>19" -- see
// asciiart/operator_symbols.txt), or 'free' (the instance's own free_text,
// verbatim). Not truncated to the block's interior width here -- render.js
// does that once it knows the width.
export function resolveLabel(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  const style = params.operator_style || 'word';
  if (style === 'id') return params.id || '';
  if (style === 'free') {
    const text = params.free_text || '';
    // Bracket-wrapping is what makes a free-text `constant` decodable at
    // all (see decode.js's DYNAMIC_LABEL_TYPES.constant for the full
    // reasoning): `constant`'s own inherent 0-input shape isn't actually a
    // safe-enough signal on its own -- any component can be given the same
    // "no top port" frame via the generic portTop=off override, confirmed
    // directly to collide for real (an unbracketed fallback mis-decoded
    // `xor[inputs=3,portTop=off]`'s own plain "XOR" word label as a
    // free-text constant). The brackets are the actual, load-bearing
    // disambiguator, scoped to `constant` alone so every other type's
    // operator_style='free' stays exactly as ambiguous/unrecoverable as
    // documented on free_text's own dedicated-bracket-*border* comment.
    return typeName === 'constant' ? `[${text}]` : text;
  }
  if (style === 'symbol' && type.symbol !== undefined) return resolve(type.symbol, params);
  return resolve(type.label, params);
}

// The "hex value" side of a free-text constant (see resolveLabel above) --
// ChaCha's own ASCII constants ("expa", "nd 3", ...) are the motivating
// case: decode.js stores *both* the literal text (`free_text`) and this
// derived hex encoding (`value`) on the same block, so a pseudocode
// extraction (which only keeps `value`, a dataflow-relevant operator
// param -- see pseudocode.js's OPERATOR_PARAM_NAMES) still gets a
// meaningful, correct value even though the readable text itself is
// style/structural and dropped there. Not reversible by design -- nothing
// here ever needs to turn a hex value back into text.
export function asciiTextToHex(text) {
  return [...text].map((ch) => ch.codePointAt(0).toString(16).padStart(2, '0')).join('');
}

export function defaultParams(typeName) {
  const type = BLOCK_TYPES[typeName];
  const params = {};
  for (const p of type.params) params[p.name] = p.default;
  return params;
}

export function resolve(field, params) {
  return typeof field === 'function' ? field(params) : field;
}

export function blockWords(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  let words;
  if (type.family === 'io' || type.family === 'swap') words = params.words;
  else if (type.family === 'wiring' || type.family === 'double_wire') return 1;
  else if (type.family === 'multiblockpermutation') return resolveMultiblockPermutation(params).words;
  else words = resolve(type.words, params);

  words = Number(words);
  if (!Number.isSafeInteger(words) || words < 1) {
    throw new Error(`Invalid words "${params.words}": expected a positive integer`);
  }
  return words;
}

// How many grid rows (each ROW_HEIGHT=5 lines) a block reserves. Every
// existing block type is exactly 1; multiblockpermutation is the only
// variable-height catalog type -- see permutationLayout.
export function blockRowSpan(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  if (type.family !== 'multiblockpermutation') return 1;
  return permutationLayout(resolveMultiblockPermutation(params), params.borders).rowSpan;
}

// A single-word component's top/left/right/bottom sides normally come from
// its `inputs` (+ `side`) catalog params, but the editor also lets a placed
// instance override any side directly (see the port-toolbar buttons in
// app.js) via `params.portTop`/`portLeft`/`portRight`/`portBottom` -- an
// explicit override always wins over the catalog-derived default. Stored
// values are 'in', 'out' (left/right/bottom only), 'off' (no connector
// there), or absent (use the catalog default). Top can only ever be 'in' or
// absent: a component's primary signal always flows in from the top, never
// out, in every example in asciiart/manual_examples/. Bottom can only ever be
// 'out' or absent (off) -- a component computes and produces a value, it
// never receives one from below; turning it off entirely (rather than just
// adding a left/right *duplicate* of it, which is what a plain left/right
// 'out' override already does) is for a block whose result is only ever
// consumed sideways, letting it sit inline in a horizontal chain instead of
// always continuing straight down (see e.g.
// asciiart/manual_examples/constructions/lai_massey's own history, or a component
// with both top and bottom off and only left/right active).
const OVERRIDE_KEYS = { top: 'portTop', left: 'portLeft', right: 'portRight', bottom: 'portBottom' };

export function componentSidePort(typeName, params, side) {
  const overrideKey = OVERRIDE_KEYS[side];
  const override = params[overrideKey];
  if (override !== undefined) return override === 'off' ? undefined : override;
  if (side === 'bottom') return 'out';
  const inputs = resolve(BLOCK_TYPES[typeName].inputs, params);
  if (side === 'top') return inputs >= 1 ? 'in' : undefined;
  if (side === 'left') return inputs >= 3 || (inputs === 2 && (params.side || 'left') === 'left') ? 'in' : undefined;
  return inputs >= 3 || (inputs === 2 && params.side === 'right') ? 'in' : undefined;
}

// value: 'in' | 'out' (left/right/bottom) | 'off'
export function setComponentSidePort(params, side, value) {
  params[OVERRIDE_KEYS[side]] = value;
}

// Returns the block's port map from the *outside*: for every side, 'in'
// (this block needs a value fed in from that direction), 'out' (this block
// produces a value in that direction) or undefined (nothing there).
// `wordIndex` (0-based) matters for multi-word components, which have an
// independent top/bottom port per word and no left/right ports at all.
export function blockPorts(typeName, params, wordIndex = 0, totalWords = 1) {
  const type = BLOCK_TYPES[typeName];
  if (type.family === 'component') {
    const ports = {};
    if (totalWords > 1) {
      const everyWord = Array.from({ length: totalWords }, (_, i) => i);
      const activeInputs = parseWordIndexList(params.activeInputs, totalWords) ?? everyWord;
      const activeOutputs = parseWordIndexList(params.activeOutputs, totalWords) ?? everyWord;
      if (resolve(type.inputs, params) >= 1 && activeInputs.includes(wordIndex)) ports.top = 'in';
      if (activeOutputs.includes(wordIndex)) ports.bottom = 'out';
      return ports;
    }
    const top = componentSidePort(typeName, params, 'top');
    const left = componentSidePort(typeName, params, 'left');
    const right = componentSidePort(typeName, params, 'right');
    const bottom = componentSidePort(typeName, params, 'bottom');
    if (top) ports.top = top;
    if (left) ports.left = left;
    if (right) ports.right = right;
    if (bottom) ports.bottom = bottom;
    return ports;
  }
  if (type.family === 'io') {
    const activeWords = resolveActiveWords(params, totalWords);
    if (!activeWords.includes(wordIndex)) return {}; // spacer word -- no port at all, see ACTIVE_WORDS_PARAM
    if (type.kind === 'input') return { bottom: 'out' };
    if (type.kind === 'output') return { top: 'in' };
    return { top: 'in', bottom: 'out' };
  }
  if (type.family === 'wiring' || type.family === 'double_wire') {
    return resolve(type.ports, params);
  }
  if (type.family === 'swap') {
    const active = resolveSwapActiveWords(params, totalWords);
    return active.includes(wordIndex) ? { top: 'in', bottom: 'out' } : {}; // spacer word -- no port at all
  }
  if (type.family === 'multiblockpermutation') {
    // Per-word now -- a spacer word (in neither list) has no ports at all,
    // and with independent activeInputs/activeOutputs a word can have just
    // one side. connectivity.js never traces internal routing, only port
    // presence, so this is exactly what a neighbor needs to check against.
    const { activeInputs, activeOutputs } = resolveMultiblockPermutation(params);
    const ports = {};
    if (activeInputs.includes(wordIndex)) ports.top = 'in';
    if (activeOutputs.includes(wordIndex)) ports.bottom = 'out';
    return ports;
  }
  return {};
}

// Direction-flip lookup for reflectParams: wire's own direction names
// already have an exact horizontal opposite (top_to_left <-> top_to_right,
// etc.); top_to_bottom is its own mirror image (a straight vertical pass has
// no left/right concept to flip).
const REWIRE_DIRECTION_MIRROR = {
  top_to_bottom: 'top_to_bottom',
  top_to_left: 'top_to_right',
  top_to_right: 'top_to_left',
  left_to_right: 'right_to_left',
  right_to_left: 'left_to_right',
  left_to_bottom: 'right_to_bottom',
  right_to_bottom: 'left_to_bottom',
};
const SPLIT_DIRECTION_MIRROR = {
  top_to_left_and_bottom: 'top_to_right_and_bottom',
  top_to_right_and_bottom: 'top_to_left_and_bottom',
  left_to_right_and_bottom: 'right_to_left_and_bottom',
  right_to_left_and_bottom: 'left_to_right_and_bottom',
  top_to_left_and_right: 'top_to_left_and_right',
  top_to_left_and_right_and_bottom: 'top_to_left_and_right_and_bottom',
};
const DOUBLE_WIRE_VARIANT_MIRROR = {
  'top_to_bottom+left_to_right': 'top_to_bottom+right_to_left',
  'top_to_bottom+right_to_left': 'top_to_bottom+left_to_right',
  'top_to_left+right_to_bottom': 'top_to_right+left_to_bottom',
  'top_to_right+left_to_bottom': 'top_to_left+right_to_bottom',
};

// Returns a new params object for typeName's instance mirrored left-right --
// e.g. a left-side input becomes a right-side input, wire's top_to_left
// becomes top_to_right -- without touching its label/symbol/free_text or any
// non-directional value (a constant's value, a rotate's amount). Identity
// for anything with no left/right concept at all (IO blocks).
export function reflectParams(typeName, params) {
  const type = BLOCK_TYPES[typeName];
  const next = { ...params };

  if (type.family === 'component') {
    const words = blockWords(typeName, next);
    if (words > 1) {
      const mirrorActive = (name) => {
        const active = parseWordIndexList(next[name], words);
        if (active === null) return; // blank means every word, unchanged by reflection
        const mirrored = active.map((i) => words - 1 - i).reverse();
        next[name] = mirrored.length ? mirrored.join(',') : 'none';
      };
      mirrorActive('activeInputs');
      mirrorActive('activeOutputs');
    }
    if (next.portLeft !== undefined || next.portRight !== undefined) {
      const left = next.portLeft;
      const right = next.portRight;
      if (right !== undefined) next.portLeft = right;
      else delete next.portLeft;
      if (left !== undefined) next.portRight = left;
      else delete next.portRight;
    }
    if ('side' in next) next.side = next.side === 'left' ? 'right' : 'left';
    if ('direction' in next) next.direction = next.direction === 'left' ? 'right' : 'left';
    if (next.narrow === 'left') next.narrow = 'right';
    else if (next.narrow === 'right') next.narrow = 'left';
    return next;
  }

  if (type.family === 'wiring') {
    if (typeName === 'split' && next.direction in SPLIT_DIRECTION_MIRROR) {
      next.direction = SPLIT_DIRECTION_MIRROR[next.direction];
    } else if (typeName === 'wire' && next.direction in REWIRE_DIRECTION_MIRROR) {
      next.direction = REWIRE_DIRECTION_MIRROR[next.direction];
    }
    return next;
  }

  if (type.family === 'double_wire' && next.variant in DOUBLE_WIRE_VARIANT_MIRROR) {
    next.variant = DOUBLE_WIRE_VARIANT_MIRROR[next.variant];
    return next;
  }

  if (type.family === 'multiblockpermutation') {
    // permutation mirrors in its own logical-index space (unaffected by
    // word positions); activeInputs/activeOutputs mirror as physical word
    // indices (i -> words-1-i, re-sorted ascending by reversing). Always
    // written out explicitly afterward -- a blank ("every word") list only
    // stays correct under reflection when words === permutation.length, so
    // it's simplest to always resolve then re-serialize rather than special-
    // case that.
    const { words, activeInputs, activeOutputs, permutation } = resolveMultiblockPermutation(next);
    const k = permutation.length;
    const mirroredPerm = new Array(k);
    for (let j = 0; j < k; j++) mirroredPerm[j] = k - 1 - permutation[k - 1 - j];
    const mirrorList = (list) =>
      list
        .map((i) => words - 1 - i)
        .reverse()
        .join(',');
    next.permutation = mirroredPerm.join(',');
    next.activeInputs = mirrorList(activeInputs);
    next.activeOutputs = mirrorList(activeOutputs);
    next.words = String(words);
    return next;
  }

  if (type.family === 'swap') {
    // Same "blank means every word, only written out explicitly afterward"
    // reasoning as multiblockpermutation above -- a blank activeWords only
    // stays correct under reflection when words is 2 (its own default), so
    // always resolve then re-serialize rather than special-casing that.
    const words = blockWords(typeName, next);
    const active = resolveSwapActiveWords(next, words);
    next.activeWords = active
      .map((i) => words - 1 - i)
      .reverse()
      .join(',');
    return next;
  }

  return next; // io, and anything else with no left/right concept: unchanged
}

// ---------------------------------------------------------------- rotate --
// Turns a side-map (only 'top'/'left'/'right'/'bottom' keys that are
// currently truthy) one quarter-turn clockwise: whatever was on the left
// edge swings up to the top, the top swings right, the right swings down to
// the bottom, and the bottom swings left. Physically: rotate the whole block
// (and whatever direction its ports face) 90 degrees clockwise, the same way
// turning a steering wheel to the right turns a north-pointing arrow to
// point east.
function rotateSides(p) {
  return { top: p.left, right: p.top, bottom: p.right, left: p.bottom };
}

function sidesKey(sides) {
  return ['top', 'left', 'right', 'bottom']
    .filter((side) => sides[side])
    .map((side) => `${side}=${sides[side]}`)
    .join(',');
}

// Reverse lookup for rotateParams's wire branch: which direction produces
// this exact side-map. (Before the identity/rewire merge this needed to
// search two separate tables and disambiguate which type to return; now
// REWIRE_PORTS is the only table and the type is always `wire`.)
function findSimpleWiringType(sides) {
  const target = sidesKey(sides);
  for (const [direction, ports] of Object.entries(REWIRE_PORTS)) {
    if (sidesKey(ports) === target) return { typeName: 'wire', direction };
  }
  return null;
}

// Rotates typeName/params one quarter-turn clockwise, skipping ahead to
// "the next valid position" (per-side rotateSides applied again) if the
// immediate quarter-turn would need a port neither componentSidePort nor
// REWIRE_PORTS ever produce (top='out' or bottom='in') -- for a `wire`,
// this can now take more than one extra step since REWIRE_PORTS has no
// bottom='in' entries at all (see its own comment), so a turn like
// top_to_left rotates through two such invalid/unrecognized intermediate
// states before landing on left_to_bottom. Returns { typeName, params } or
// null if this family has no rotation concept (io, split, double_wire,
// swap, multiblockpermutation -- none of these are single, simple enough
// directional passes for "rotate" to have one obvious meaning).
export function rotateParams(typeName, params) {
  const type = BLOCK_TYPES[typeName];

  if (type.family === 'component' && blockWords(typeName, params) === 1) {
    let cur = {
      top: componentSidePort(typeName, params, 'top'),
      right: componentSidePort(typeName, params, 'right'),
      bottom: componentSidePort(typeName, params, 'bottom'),
      left: componentSidePort(typeName, params, 'left'),
    };
    for (let i = 0; i < 4; i++) {
      cur = rotateSides(cur);
      if (cur.top === 'out') continue; // invalid -- try the next quarter-turn instead
      const next = { ...params };
      setComponentSidePort(next, 'top', cur.top || 'off');
      setComponentSidePort(next, 'right', cur.right || 'off');
      setComponentSidePort(next, 'bottom', cur.bottom || 'off');
      setComponentSidePort(next, 'left', cur.left || 'off');
      return { typeName, params: next };
    }
    return null; // unreachable -- at most one of the 4 quarter-turns is ever invalid
  }

  if (typeName === 'wire') {
    let cur = { ...REWIRE_PORTS[params.direction] };
    for (let i = 0; i < 4; i++) {
      cur = rotateSides(cur);
      if (cur.top === 'out') continue;
      const found = findSimpleWiringType(cur);
      if (!found) continue; // an intermediate state with bottom='in' -- not a real direction, keep rotating
      const next = { ...params, direction: found.direction };
      return { typeName: 'wire', params: next };
    }
    return null; // unreachable -- every direction reaches a valid, recognized state within 4 quarter-turns
  }

  return null;
}
