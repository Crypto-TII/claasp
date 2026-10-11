// The inverse of render.js: given raw ASCII text (a full example file),
// reconstructs a grid.js Grid of real catalog blocks.
//
// This works because rendering is a pure function of (type, params) alone --
// no block's glyphs depend on its neighbors (see render.js's header comment)
// -- so every (type, params) combination has one fixed, unique 5-line
// signature at a given width. Decoding a file is just: at each column of
// each 5-line row-band, try every known signature (widest first) and see
// which one matches the text there.
//
// Almost unique: a handful of signatures aren't unique at all -- an
// invisible-border `double_wire[variant=top_to_bottom+left_to_right]`
// (straight+straight, i.e. what used to be `cross`) vs. its mirror image, an
// invisible-border `wire[direction=left_to_right]` vs. `wire[direction=
// right_to_left]`, or `split[direction=left_to_right_and_bottom]` vs.
// `split[direction=right_to_left_and_bottom]` all render byte-identically
// (see render.js's renderWiring: the direction-glyph is only drawn when
// borders are visible). scanGrid records these as provisional placements
// instead of guessing; resolveAmbiguousDirections below resolves them
// afterwards by recursively tracing the wiring graph (via connectivity.js's
// same adjacency model) out to a neighbor whose own direction *is* clear,
// and only reports an error if that trace finds a genuine contradiction (or
// never finds a clear anchor at all).
//
// Used to let the palette's "Library" entries be inserted into the editor as
// real, individually-editable blocks rather than an opaque image. If a file
// contains something outside what render.js's catalog can produce, decoding
// throws -- callers should fall back to Grid#placeRawBlock instead of
// silently producing a wrong/partial structure.
import { BLOCK_TYPES, allParamCombos, blockWords, blockPorts, defaultParams, setComponentSidePort, rotateParams, asciiTextToHex, resolveSwapActiveWords } from './blockCatalog.js';
import { renderBlock, ROW_HEIGHT, WORD_WIDTH } from './render.js';
import { Grid } from './grid.js';
import { OPPOSITE_SIDE, NEIGHBOR_OFFSET, localWordIndex } from './connectivity.js';

// Building every (typeName x paramCombo x width) entry is O(types x combos x
// maxWords) -- confirmed via direct profiling to matter: candidates(175) on
// a real wide synthesized diagram took ~17s and ~39,000 entries on its own,
// before this file's own scanGrid ever runs. Caching by exact maxWords (the
// original design) rebuilds that whole cost from scratch for every distinct
// width a caller asks for -- fine for a single file, but a corpus sweep
// (verify-library-format.mjs et al.) decodes ~180 files spanning many
// different widths, none of which reused each other's cache entry even when
// their ranges overlapped almost completely.
//
// masterEntries grows incrementally instead: each call extends it only by
// the NEW widths beyond whatever's already been built (never rebuilding
// widths already covered), and a later smaller-maxWords call filters the
// existing superset rather than rebuilding. Preserves the exact tie-break
// order .find()'s original single callers relied on (see
// tiedOptionsHaveDistinctPorts/`tied[0]`): for any one fixed `words` value,
// every type's entry at that width is still added in the same
// typeName-then-paramCombo order, all within whichever single extension
// call's range covers that width -- so entries sharing a words value keep
// the exact same relative order a one-shot build would have produced,
// exactly what Array.prototype.sort's stability needs to keep tie-breaking
// unaffected. Fixed-width (non-number `words` param) types don't depend on
// maxWords at all, so they're built exactly once, on the very first
// extension, instead of redundantly on every call.
const candidatesCache = new Map(); // maxWords -> sorted, filtered view (memoized per exact value asked for)
const exactWidthCache = new Map();
function candidatesAtWidth(width) {
  if (exactWidthCache.has(width)) return exactWidthCache.get(width);
  const entries = [];
  for (const [typeName, type] of Object.entries(BLOCK_TYPES)) {
    if (typeName === 'multiblockpermutation' || typeName === 'swap') continue;
    const definition = type.params.find(p => p.name === 'words');
    for (const params of allParamCombos(typeName)) {
      const resolved = definition?.kind === 'number' ? { ...params, words: width } : params;
      if (definition?.kind === 'number' && width < (definition.min ?? 1)) continue;
      const words = blockWords(typeName, resolved);
      if (words === width) entries.push({typeName, params:resolved, words, rendered:renderBlock(typeName,resolved).join('\n')});
    }
  }
  exactWidthCache.set(width, entries);
  return entries;
}
let masterMaxWidth = 0;
let masterEntries = [];

function extendCandidatesTo(maxWords) {
  const isFirstEver = masterMaxWidth === 0;
  for (const typeName of Object.keys(BLOCK_TYPES)) {
    if (typeName === 'multiblockpermutation') continue; // variable width/height, unlike every other type -- recognized by its own dedicated pass, see tryMultiBlockPermutationMatch
    if (typeName === 'swap') continue; // variable width now too, and a blank activeWords is only valid at words=2 -- recognized by its own dedicated pass, see tryPartialSwapMatch
    for (const params of allParamCombos(typeName)) {
      const wordsParam = BLOCK_TYPES[typeName].params.find((p) => p.name === 'words');
      if (wordsParam?.kind === 'number') {
        const min = wordsParam.min ?? 1;
        for (let width = Math.max(min, masterMaxWidth + 1); width <= maxWords; width++) {
          const resolvedParams = { ...params, words: width };
          const words = blockWords(typeName, resolvedParams);
          masterEntries.push({ typeName, params: resolvedParams, words, rendered: renderBlock(typeName, resolvedParams).join('\n') });
        }
      } else if (isFirstEver) {
        const words = blockWords(typeName, params);
        masterEntries.push({ typeName, params, words, rendered: renderBlock(typeName, params).join('\n') });
      }
    }
  }
  masterMaxWidth = maxWords;
}

function candidates(maxWords = 1) {
  if (candidatesCache.has(maxWords)) return candidatesCache.get(maxWords);
  if (maxWords > masterMaxWidth) extendCandidatesTo(maxWords);
  const list = maxWords === masterMaxWidth ? masterEntries.slice() : masterEntries.filter((c) => c.words <= maxWords);
  list.sort((a, b) => b.words - a.words); // widest first, so a wide match wins over a coincidental narrow one
  candidatesCache.set(maxWords, list);
  return list;
}

// Symbol-style rotate/shift/constant/variable{rotate,shift} embed an
// open-ended value (a rotation amount, a hex constant) in their label, so
// they can't be enumerated into `candidates()` like every other block --
// there's no bound on the value. Instead: render each with a placeholder
// value to get its structural template (rows 0/1/3/4 and row2's frame/edges
// never depend on the value, only row2's interior text does), and when a
// cell's structure matches one of these templates, regex the actual
// interior text back out to recover the real params. See
// asciiart/operator_symbols.txt for the symbol formats.
// The amount may be space-padded for column alignment against neighboring
// blocks (e.g. ">>> 1" next to ">>>19") -- see
// asciiart/manual_examples/primitives/ascon/ascon_linear_layer.asciiart.
const DYNAMIC_LABEL_TYPES = {
  rotate: { pattern: /^(<<<|>>>)\s*(\d+)$/, toParams: (m) => ({ direction: m[1] === '<<<' ? 'left' : 'right', amount: Number(m[2]) }) },
  shift: { pattern: /^(<<|>>)\s*(\d+)$/, toParams: (m) => ({ direction: m[1] === '<<' ? 'left' : 'right', amount: Number(m[2]) }) },
  variablerotate: { pattern: /^(<<<|>>>)$/, toParams: (m) => ({ direction: m[1] === '<<<' ? 'left' : 'right' }) },
  variableshift: { pattern: /^(<<|>>)$/, toParams: (m) => ({ direction: m[1] === '<<' ? 'left' : 'right' }) },
  // Two alternatives: a hex value (symbol style, e.g. "x4B"), or a
  // bracketed free-text value (resolveLabel in blockCatalog.js always
  // writes this form, e.g. "[expa]" for ChaCha's own ASCII constants).
  // The brackets are load-bearing, not just readability -- a version of
  // this that also accepted *bare*, unbracketed text was tried and
  // reverted after it broke a real, unrelated fixture: any component
  // whose top port is explicitly turned off via the generic portTop=off
  // override (not just `constant`'s own inherent 0-input shape) renders
  // the exact same "no top connector" frame, so bare text alone can't
  // tell a `constant` apart from e.g. `xor[inputs=3,portTop=off]` showing
  // its own plain "XOR" word label -- confirmed directly: the bare
  // fallback silently mis-decoded that exact fixture as a free-text
  // constant. Brackets are the only genuinely unambiguous signal here.
  // Either way this always ends up filling `value` (the operator param
  // pseudocode.js keeps), derived from the text via asciiTextToHex
  // alongside the literal text itself in `free_text`, so neither
  // representation is lost.
  constant: {
    pattern: /^(?:x([0-9a-fA-F]+)|\[(.*)\])$/,
    toParams: (m) => (m[1] !== undefined ? { value: m[1] } : { operator_style: 'free', free_text: m[2], value: asciiTextToHex(m[2]) }),
  },
};

const dynamicTemplatesCache = new Map();
function dynamicTemplates(maxWords = 1) {
  if (dynamicTemplatesCache.has(maxWords)) return dynamicTemplatesCache.get(maxWords);
  const list = [];
  for (const typeName of Object.keys(DYNAMIC_LABEL_TYPES)) {
    const wordsParam = BLOCK_TYPES[typeName].params.find((p) => p.name === 'words');
    // rotate/shift can span several merged word-slots (see blockCatalog.js's
    // own `words` comment on rotate) -- try every width, not just the
    // words=1 default, the same way a fixed-label candidate is enumerated
    // per param combo in candidates() above.
    // Every DYNAMIC_LABEL_TYPES member's own `words` param is kind:'number'
    // (confirmed directly, not assumed) -- no non-number/absent branch is
    // ever reachable here.
    const wordsOptions = Array.from({ length: maxWords - (wordsParam.min ?? 1) + 1 }, (_, i) => i + (wordsParam.min ?? 1));
    for (const words of wordsOptions) {
      const params = defaultParams(typeName);
      params.operator_style = 'symbol';
      if ('amount' in params) params.amount = 1;
      if ('value' in params) params.value = '00';
      if (words !== undefined) params.words = words;
      list.push({ typeName, lines: renderBlock(typeName, params), words: blockWords(typeName, params) });
    }
  }
  dynamicTemplatesCache.set(maxWords, list);
  return list;
}

// ' ' -> no port, '-' -> an *additional* side output (see blockCatalog.js's
// componentSidePort), '>'/'<' -> a side input -- same glyph vocabulary as
// every other component, just derived here instead of compared against a
// fixed template, since a dynamic-label block can carry the same left/right
// port overrides as any other component (see e.g. this file's constant with
// an extra left output).
function edgePort(glyph, side) {
  if (glyph === ' ') return 'off';
  if (glyph === '-') return 'out';
  if (side === 'left' && glyph === '>') return 'in';
  if (side === 'right' && glyph === '<') return 'in';
  return null; // not a recognized connector glyph at all -- not a match
}

function tryDynamicLabelMatch(bandLines, col, totalWords) {
  if (bandLines[2][col * WORD_WIDTH + 1] !== '|') return null;
  for (const tmpl of dynamicTemplates(totalWords - col)) {
    if (col + tmpl.words > totalWords) continue;
    const width = tmpl.words * WORD_WIDTH;
    const slice = bandLines.map((l) => l.substr(col * WORD_WIDTH, width));
    const continuation = tmpl.typeName === 'constant' && /^x[0-9a-fA-F]+$/.test(slice[1].slice(2, width - 2).trim());
    if (slice[0] !== tmpl.lines[0] || (!continuation && slice[1] !== tmpl.lines[1]) || slice[3] !== tmpl.lines[3] || slice[4] !== tmpl.lines[4]) continue;
    if (continuation && (slice[1].slice(0,2) !== tmpl.lines[1].slice(0,2) || slice[1].slice(width-2) !== tmpl.lines[1].slice(width-2))) continue;

    const actualRow2 = slice[2];
    const expectedRow2 = tmpl.lines[2];
    if (actualRow2[1] !== expectedRow2[1] || actualRow2[width - 2] !== expectedRow2[width - 2]) continue; // frame pipes

    const leftPort = edgePort(actualRow2[0], 'left');
    const rightPort = edgePort(actualRow2[width - 1], 'right');
    if (leftPort === null || rightPort === null) continue;

    const interior = (continuation ? slice[1].slice(2, width - 2).trim() : '') + actualRow2.slice(2, width - 2).trim();
    const spec = DYNAMIC_LABEL_TYPES[tmpl.typeName];
    const match = spec.pattern.exec(interior);
    if (!match) continue;

    const params = defaultParams(tmpl.typeName);
    params.operator_style = 'symbol';
    if ('words' in params) params.words = tmpl.words;
    Object.assign(params, spec.toParams(match));
    setComponentSidePort(params, 'left', leftPort);
    setComponentSidePort(params, 'right', rightPort);
    return { typeName: tmpl.typeName, params, words: tmpl.words };
  }
  return null;
}

// free_text (blockCatalog.js) is the one catalog type whose entire interior
// is arbitrary text with no regex shape to anchor on (unlike rotate's
// ">>>19" above) -- what makes it decodable anyway is its `[`/`]` frame
// (shape: 'bracket'), which no other type ever renders, so matching those
// two exact characters is itself the whole "is this a free_text block?"
// test. Same interior/padding-ambiguity caveat as every other label
// (leading/trailing spaces in the original text can't be told apart from
// centering padding once decoded back).
//
// free_text's own `narrow` param (see blockCatalog.js) changes rows 0/1/3's
// actual shape, not just a masked-out glyph -- so unlike top/bottom
// (independent toggles layered on any shape), each narrow value needs its
// own template tried in turn. Only meaningful at words===1 though (render.js
// never applies narrow past a single word) -- a wider free_text box is
// tried first, by tryMultiWordFreeTextMatch below.
const FREE_TEXT_NARROW_OPTIONS = ['none', 'bottom', 'left', 'right'];
let freeTextTemplatesCache = null;
function freeTextTemplates() {
  if (!freeTextTemplatesCache) {
    freeTextTemplatesCache = FREE_TEXT_NARROW_OPTIONS.map((narrow) => ({
      narrow,
      lines: renderBlock('free_text', { ...defaultParams('free_text'), text: '', narrow }),
    }));
  }
  return freeTextTemplatesCache;
}

// Blanks a row's centre column (index 5) so two renderings that only
// differ by a top/bottom port override -- 'v'/'_' on row 0, '|'/blank on
// row 4, the only two states componentSidePort ever produces for either
// side -- still compare equal. Shared by tryFreeTextMatch and coreOf below.
function maskCentre(row) {
  return row.slice(0, 5) + ' ' + row.slice(6);
}

// A wide free_text box (words > 1, e.g. a generic multi-word round function
// standing in for several components at once) forces narrow='none' --
// render.js's renderComponent only ever applies narrow to a single-word
// component -- so unlike the words===1 branch below there's exactly one
// frame shape to try per width, but top/bottom activity can still vary per
// word via the same activeInputs/activeOutputs mechanism every other
// multi-word component family type uses (see blockCatalog.js's
// blockPorts), even though free_text's own catalog entry doesn't expose
// them as editable params. Same "infer active words from their glyph rows,
// then verify by re-rendering" approach as tryPartialComponentMatch --
// free_text can't just be one more candidates() entry there because its
// `text` is open-ended, not enumerable ahead of time.
function tryMultiWordFreeTextMatch(bandLines, col, totalWords) {
  const maxWords = totalWords - col;
  for (let words = maxWords; words >= 2; words--) {
    const width = words * WORD_WIDTH;
    const slice = bandLines.map((l) => l.substr(col * WORD_WIDTH, width));
    if (slice[2][1] !== '[' || slice[2][width - 2] !== ']') continue; // free_text's own bracket frame, see its header comment

    const activeInputs = extractActiveIndices(slice[0], words, 'v', borderBackground);
    const activeOutputs = extractActiveIndices(slice[4], words, '|', blankBackground);
    if (!activeInputs || !activeOutputs) continue;

    const serialize = (active) => (active.length === words ? '' : active.length ? active.join(',') : 'none');
    const params = {
      ...defaultParams('free_text'),
      words,
      text: slice[2].slice(2, width - 2).trim(),
      activeInputs: serialize(activeInputs),
      activeOutputs: serialize(activeOutputs),
    };
    let rendered;
    try {
      rendered = renderBlock('free_text', params);
    } catch {
      continue;
    }
    if (rendered.join('\n') === slice.join('\n')) {
      return { typeName: 'free_text', params, words };
    }
  }
  return null;
}

function tryFreeTextMatch(bandLines, col, totalWords) {
  if (bandLines[2][col * WORD_WIDTH + 1] !== '[') return null;
  const multiWordMatch = tryMultiWordFreeTextMatch(bandLines, col, totalWords);
  if (multiWordMatch) return multiWordMatch;

  if (col + 1 > totalWords) return null;
  const width = WORD_WIDTH;
  const slice = bandLines.map((l) => l.substr(col * WORD_WIDTH, width));

  for (const tmpl of freeTextTemplates()) {
    const t = tmpl.lines;
    // Row 1 and row 3 are fully determined by `narrow` (never by top/bottom
    // on their own -- see renderComponent, whose l3 never varies with
    // bottom's in/out/off), so both must match exactly; only row 0's centre
    // glyph (top) is independently masked here.
    if (maskCentre(slice[0]) !== maskCentre(t[0]) || slice[1] !== t[1] || slice[3] !== t[3]) continue;

    const topGlyph = slice[0][5];
    if (topGlyph !== 'v' && topGlyph !== '_') continue;

    let bottomPort;
    if (tmpl.narrow === 'bottom') {
      // A bottom taper *is* the active output -- bottom can't independently
      // be in/off here, so row 4 must match the template exactly.
      if (slice[4] !== t[4]) continue;
      bottomPort = 'out';
    } else {
      const bottomGlyph = slice[4][5];
      if (bottomGlyph !== '|' && bottomGlyph !== '^' && bottomGlyph !== ' ') continue;
      bottomPort = bottomGlyph === '|' ? 'out' : bottomGlyph === '^' ? 'in' : 'off';
    }

    const actualRow2 = slice[2];
    const expectedRow2 = t[2];
    if (actualRow2[1] !== expectedRow2[1] || actualRow2[width - 2] !== expectedRow2[width - 2]) continue; // '[' / ']'

    const leftPort = edgePort(actualRow2[0], 'left');
    const rightPort = edgePort(actualRow2[width - 1], 'right');
    if (leftPort === null || rightPort === null) continue;

    const params = defaultParams('free_text');
    params.text = actualRow2.slice(2, width - 2).trim();
    params.narrow = tmpl.narrow;
    setComponentSidePort(params, 'left', leftPort);
    setComponentSidePort(params, 'right', rightPort);
    setComponentSidePort(params, 'top', topGlyph === 'v' ? 'in' : 'off');
    setComponentSidePort(params, 'bottom', bottomPort);
    return { typeName: 'free_text', params, words: 1 };
  }
  return null;
}

// Blanks out a single-word component's left/right edges (row2's first and
// last characters), its top connector (row0's centre column -- 'v' when
// active, '_' when portTop='off') and its bottom connector (row4's centre
// column -- '|' when active, blank when portBottom='off') -- the only two
// states componentSidePort ever produces for top/bottom -- so two
// renderings that only differ by a port override still compare equal. Used
// by tryFixedLabelCoreMatch below to recognize a component with a port
// override (see blockCatalog.js's componentSidePort) -- something that
// isn't in candidates() at all, since overrides aren't declared catalog
// params and so aren't enumerated by allParamCombos().
function coreOf(lines) {
  const row2 = ' ' + lines[2].slice(1, WORD_WIDTH - 1) + ' ';
  return [maskCentre(lines[0]), lines[1], row2, lines[3], maskCentre(lines[4])].join('\n');
}

// For most component types, rotating never changes anything coreOf doesn't
// already mask out (top/bottom overrides), so the base candidate's own core
// covers every rotation for free. The one exception is a `narrow` that
// tracks its output side (see blockCatalog.js's narrowTowardOutput): rotated
// onto left/right, it reshapes row1/row3 into the taper geometry those rows
// don't otherwise have, which coreOf's masking (centre column only) can't
// paper over. So besides the base candidate, also index up to 3 further
// quarter-turns (via rotateParams) under their own, independently-computed
// core -- covering a rotated surjective xor/and/or/mod-op/sbox the same way
// tryFreeTextMatch's own template loop covers free_text's explicit narrow.
function rotationFamily(typeName, params) {
  const family = [{ typeName, params }];
  let cur = { typeName, params };
  for (let i = 0; i < 3; i++) {
    const next = rotateParams(cur.typeName, cur.params);
    if (!next) break;
    if (next.typeName === typeName && JSON.stringify(next.params) === JSON.stringify(params)) break; // back to the start
    family.push(next);
    cur = next;
  }
  return family;
}

let coreCandidatesCache = null;
function coreCandidates() {
  if (coreCandidatesCache) return coreCandidatesCache;
  const base = candidates().filter((c) => c.words === 1 && BLOCK_TYPES[c.typeName].family === 'component' && !(c.typeName in DYNAMIC_LABEL_TYPES));
  const all = [];
  for (const c of base) {
    for (const variant of rotationFamily(c.typeName, c.params)) {
      const rendered = renderBlock(variant.typeName, variant.params).join('\n');
      all.push({ typeName: variant.typeName, params: variant.params, words: 1, core: coreOf(rendered.split('\n')) });
    }
  }
  coreCandidatesCache = all;
  return coreCandidatesCache;
}

function tryFixedLabelCoreMatch(bandLines, col, totalWords) {
  if (col + 1 > totalWords) return null;
  const slice = bandLines.map((l) => l.substr(col * WORD_WIDTH, WORD_WIDTH));
  const actualCore = coreOf(slice);
  const match = coreCandidates().find((c) => c.core === actualCore);
  if (!match) return null;

  const leftPort = edgePort(slice[2][0], 'left');
  const rightPort = edgePort(slice[2][WORD_WIDTH - 1], 'right');
  if (leftPort === null || rightPort === null) return null;

  const topGlyph = slice[0][5];
  if (topGlyph !== 'v' && topGlyph !== '_') return null; // componentSidePort's top is only ever 'in' (v) or 'off' (_), see its own comment
  const topPort = topGlyph === 'v' ? 'in' : 'off';

  const bottomGlyph = slice[4][5];
  if (bottomGlyph !== '|' && bottomGlyph !== '^' && bottomGlyph !== ' ') return null; // componentSidePort's bottom is 'out' (|), a rotated 'in' (^), or 'off' (blank)
  const bottomPort = bottomGlyph === '|' ? 'out' : bottomGlyph === '^' ? 'in' : 'off';

  const params = { ...match.params };
  setComponentSidePort(params, 'left', leftPort);
  setComponentSidePort(params, 'right', rightPort);
  setComponentSidePort(params, 'top', topPort);
  setComponentSidePort(params, 'bottom', bottomPort);
  return { typeName: match.typeName, params, words: 1 };
}

function normalizeLines(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  if (lines.length === 0) throw new Error('Empty file.');
  if (lines.length % ROW_HEIGHT !== 0) {
    throw new Error(`Line count (${lines.length}) isn't a multiple of ${ROW_HEIGHT} -- not a valid block grid.`);
  }
  const width = Math.max(...lines.map((l) => l.length));
  if (width % WORD_WIDTH !== 0) {
    throw new Error(`Line width (${width}) isn't a multiple of ${WORD_WIDTH} -- not a valid block grid.`);
  }
  return lines.map((l) => l.padEnd(width, ' '));
}

// Fallback for text decodeGrid() can't fully decompose: a single opaque
// block descriptor (see Grid#placeRawBlock) covering the whole file.
export function asRawBlock(label, text) {
  const lines = normalizeLines(text);
  return { row: 0, col: 0, raw: true, type: label, lines, words: lines[0].length / WORD_WIDTH, rowSpan: lines.length / ROW_HEIGHT };
}

// Several tied candidates can share one rendered signature for reasons that
// have nothing to do with direction ambiguity -- e.g. `xor[inputs=3]`'s
// `side` param is meaningless once both sides are already active, and
// `output[words=1]`'s `merged` param only affects words>1 -- so those tie
// only because the *unused* param varies, not because the block's actual
// meaning (its ports) is unrecoverable from the text. Only a genuine port
// disagreement (any word, any side) is worth resolving via
// resolveAmbiguousDirections; anything else is fine to leave as whichever
// candidate happened to match first.
function tiedOptionsHaveDistinctPorts(tied) {
  const base = tied[0];
  for (let w = 0; w < base.words; w++) {
    const baseSidePorts = blockPorts(base.typeName, base.params, w, base.words);
    for (let i = 1; i < tied.length; i++) {
      const otherSidePorts = blockPorts(tied[i].typeName, tied[i].params, w, tied[i].words);
      for (const side of ['top', 'bottom', 'left', 'right']) {
        if (baseSidePorts[side] !== otherSidePorts[side]) return true;
      }
    }
  }
  return false;
}

// multiblockpermutation is variable width *and* height, so it can't go
// through the fixed-signature candidates() list at all (see the skip in
// candidates() above). Recognized instead by: (1) find the widest word-count
// (words) whose row-0 structurally matches a v-row (border style + a subset
// of word-centres showing 'v') at (rb, col), extracting activeInputs
// directly from which centres are lit; (2) try successive row-band heights
// until the last line structurally matches a pipe-row, extracting
// activeOutputs the same way (and, for visible borders, checking the
// second-to-last line is a plain border row); (3) parse the lines between
// into swap-lines/directional-lines (a maximal run of -/</>/o characters,
// classified by its first+last character and which of activeInputs/
// activeOutputs its endpoints belong to) and reconstruct the permutation
// those imply, including silent same-column pass-throughs; (4) accept only
// if re-rendering that recovered (words, activeInputs, activeOutputs,
// permutation, borders) via renderBlock reproduces the extracted text
// *exactly* -- this is what actually enforces every rule in
// asciiart/notes.md's "Multi-block permutations"/"Partial input/output
// connectors" sections (word-centre alignment, no two overlapping lines
// sharing a row, canonical swap-vs-directed form, self-alignment required
// for a swap) without re-implementing each one separately.
const RUN_CHARS = new Set(['-', '<', '>', 'o']);

function findRuns(line) {
  const runs = [];
  let start = -1;
  for (let i = 0; i <= line.length; i++) {
    const isRunChar = i < line.length && RUN_CHARS.has(line[i]);
    if (isRunChar && start === -1) start = i;
    if (!isRunChar && start !== -1) {
      runs.push([start, i - 1]);
      start = -1;
    }
  }
  return runs;
}

// A run's two endpoint glyphs classify it as a swap (both '<'/'>') or a
// directed edge (one 'o', one '<'/'>' -- 'o' marks the source). Returns raw
// word indices (not yet checked against activeInputs/activeOutputs -- see
// parsePermutationContent) or null if malformed (unaligned, wrong glyphs,
// or non-dash filler).
function classifyRun(line, start, end) {
  if ((start - 5) % WORD_WIDTH !== 0 || (end - 5) % WORD_WIDTH !== 0) return null;
  const leftWord = (start - 5) / WORD_WIDTH;
  const rightWord = (end - 5) / WORD_WIDTH;
  if (!Number.isInteger(leftWord) || !Number.isInteger(rightWord) || rightWord <= leftWord) return null;
  for (let i = start + 1; i < end; i++) {
    if (line[i] !== '-') return null;
  }
  const first = line[start];
  const last = line[end];
  if (first === '<' && last === '>') return { type: 'swap', a: leftWord, b: rightWord };
  if (first === 'o' && last === '>') return { type: 'edge', src: leftWord, dst: rightWord };
  if (first === '<' && last === 'o') return { type: 'edge', src: rightWord, dst: leftWord };
  return null;
}

// Row-text validator/extractor: checks a row matches "every non-centre
// column is `bg(c, width)`, every word-centre is either `glyph` or
// `bg(c, width)`" and returns the sorted list of word indices where `glyph`
// was found -- or null if the row doesn't fit that shape at all (a stray
// character anywhere). Used for both the v-row (glyph='v') and the
// pipe-row/terminator (glyph='|'), which share this exact shape, just with
// different backgrounds/glyphs.
function extractActiveIndices(rowText, words, glyph, bg) {
  const width = words * WORD_WIDTH;
  if (rowText.length !== width) return null;
  const active = [];
  for (let c = 0; c < width; c++) {
    const wordIdx = (c - 5) / WORD_WIDTH;
    const isCentre = Number.isInteger(wordIdx) && wordIdx >= 0 && wordIdx < words;
    const expectedBg = bg(c, width);
    if (isCentre && rowText[c] === glyph) {
      active.push(wordIdx);
    } else if (rowText[c] !== expectedBg) {
      return null;
    }
  }
  return active;
}

const blankBackground = () => ' ';
const borderBackground = (c, width) => (c === 0 || c === 1 || c === width - 2 || c === width - 1 ? ' ' : '_');

function isPlainBorderRow(rowText, width) {
  if (rowText.length !== width) return false;
  for (let c = 0; c < width; c++) {
    const expected = c === 0 || c === width - 1 ? ' ' : c === 1 || c === width - 2 ? '|' : '_';
    if (rowText[c] !== expected) return false;
  }
  return true;
}

// Parses the content between a multiblockpermutation's row-0 and terminator
// (excluding the border-closing row in visible mode, already stripped by
// the caller) into a permutation array over activeInputs/activeOutputs'
// index space, or null if anything doesn't fit the grammar: an unaligned/
// malformed run, a swap whose endpoints aren't self-aligned (each its own
// input AND output at the same column), an edge endpoint that isn't
// actually an active input/output, two edges disagreeing about the same
// logical input or output, or a leftover active input/output that has
// neither an explicit edge nor a same-column silent pass-through available.
function parsePermutationContent(middleLines, activeInputs, activeOutputs) {
  const k = activeInputs.length;
  const perm = new Array(k).fill(null);
  const srcUsed = new Set(); // logical input indices already assigned a destination
  const dstUsed = new Set(); // logical output indices already assigned a source
  const inputIndexOf = (col) => activeInputs.indexOf(col);
  const outputIndexOf = (col) => activeOutputs.indexOf(col);

  const assign = (i, j) => {
    if (i < 0 || j < 0 || srcUsed.has(i) || dstUsed.has(j)) return false;
    srcUsed.add(i);
    dstUsed.add(j);
    perm[i] = j;
    return true;
  };

  for (const line of middleLines) {
    for (const [start, end] of findRuns(line)) {
      const edge = classifyRun(line, start, end);
      if (!edge) return null;
      if (edge.type === 'swap') {
        // A swap-line only ever replaces a mutual pair where both words are
        // self-aligned (their own input and output share a column) -- see
        // multiblockPermutationEdges in blockCatalog.js.
        const aIn = inputIndexOf(edge.a);
        const aOut = outputIndexOf(edge.a);
        const bIn = inputIndexOf(edge.b);
        const bOut = outputIndexOf(edge.b);
        if (aIn < 0 || aOut < 0 || bIn < 0 || bOut < 0) return null;
        if (!assign(aIn, bOut) || !assign(bIn, aOut)) return null;
      } else {
        const i = inputIndexOf(edge.src);
        const j = outputIndexOf(edge.dst);
        if (!assign(i, j)) return null;
      }
    }
  }

  // Every active input not yet claimed by an explicit edge must be a silent
  // same-column pass-through: its own column must also be an active output,
  // unclaimed, and become its destination.
  for (let i = 0; i < k; i++) {
    if (srcUsed.has(i)) continue;
    const j = outputIndexOf(activeInputs[i]);
    if (!assign(i, j)) return null;
  }
  return perm.every((v) => v !== null) ? perm : null;
}

// input/output/intermediate_output's activeWords (blockCatalog.js) is
// open-ended (kind:'text'), so a genuinely partial instance -- some words
// spacers -- isn't in candidates() at all (only the "every word active,
// activeWords blank" combo is). Recognized the same "hypothesize the active
// set from whichever glyph row is actually present, then render+compare"
// way tryMultiBlockPermutationMatch does above, just for a fixed (non-
// variable-height) shape -- no separate row needed per direction, since an
// io block only ever has one meaningful side (input: bottom; output: top;
// intermediate_output: both, driven by the same active set).
const IO_KIND_GLYPH_ROW = { input: { line: 3, glyph: '|', bg: blankBackground }, output: { line: 1, glyph: 'v', bg: borderBackground }, intermediate_output: { line: 1, glyph: 'v', bg: borderBackground } };

function tryPartialIoMatch(bandLines, col, totalWords) {
  // Every I/O shape, including all-inactive and partial wide boxes, has
  // this underscore in its border row. Empty routing cells do not: avoid
  // rendering every possible empty wide I/O hypothesis at those cells.
  if (bandLines[1][col * WORD_WIDTH + 2] !== '_') return null;
  const maxWords = totalWords - col;
  for (let words = maxWords; words >= 1; words--) {
    const slice = bandLines.map((l) => l.substr(col * WORD_WIDTH, words * WORD_WIDTH));
    for (const kind of ['input', 'output', 'intermediate_output']) {
      const { line, glyph, bg } = IO_KIND_GLYPH_ROW[kind];
      const active = extractActiveIndices(slice[line], words, glyph, bg);
      if (!active || active.length === words) continue; // full-width match is already covered by candidates()

      const secrecyOptions = kind === 'input' ? ['public', 'secret'] : [undefined];
      for (const secrecy of secrecyOptions) {
        const params = { ...defaultParams(kind), words, activeWords: active.length ? active.join(',') : 'none' };
        if (secrecy) params.secrecy = secrecy;
        let rendered;
        try {
          rendered = renderBlock(kind, params);
        } catch {
          continue;
        }
        if (rendered.join('\n') === slice.join('\n')) {
          return { typeName: kind, params, words };
        }
      }
    }
  }
  return null;
}

// swap is excluded from candidates() (see the skip in candidates() above --
// same reason as multiblockpermutation) since it's variable-width now too,
// and a blank activeWords is only a valid render at words=2. Try
// progressively narrower widths, read the 2 active columns straight off
// row 0's pipe glyphs (rows 1/3/4 must match identically, confirmed by
// re-rendering the whole candidate), same technique as tryPartialIoMatch.
function tryPartialSwapMatch(bandLines, col, totalWords) {
  const maxWords = totalWords - col;
  for (let words = maxWords; words >= 2; words--) {
    const slice = bandLines.map((l) => l.substr(col * WORD_WIDTH, words * WORD_WIDTH));
    const active = extractActiveIndices(slice[0], words, '|', blankBackground);
    if (!active || active.length !== 2) continue;
    const params = { ...defaultParams('swap'), words, activeWords: active.join(',') };
    let rendered;
    try {
      rendered = renderBlock('swap', params);
    } catch {
      continue;
    }
    if (rendered.join('\n') === slice.join('\n')) {
      return { typeName: 'swap', params, words };
    }
  }
  return null;
}

// Multi-word components can independently omit top inputs and bottom
// outputs. Infer both connector sets from their glyph rows, then verify the
// entire candidate by re-rendering it so labels, frames, and every other
// parameter still have to match exactly.
function tryPartialComponentMatch(bandLines, col, totalWords, candidateList) {
  const remaining = totalWords - col;
  if (bandLines[0][col * WORD_WIDTH + 2] !== '_') return null;
  for (const candidate of candidateList || candidates(remaining)) {
    if (candidate.words > remaining) continue;
    if (candidate.words <= 1 || BLOCK_TYPES[candidate.typeName].family !== 'component') continue;
    const width = candidate.words * WORD_WIDTH;
    const slice = bandLines.map((line) => line.substr(col * WORD_WIDTH, width));
    const activeInputs = extractActiveIndices(slice[0], candidate.words, 'v', borderBackground);
    const activeOutputs = extractActiveIndices(slice[4], candidate.words, '|', blankBackground);
    if (!activeInputs || !activeOutputs) continue;
    if (activeInputs.length === candidate.words && activeOutputs.length === candidate.words) continue;
    const serialize = (active) => active.length === candidate.words ? '' : active.length ? active.join(',') : 'none';
    const params = {
      ...candidate.params,
      words: candidate.words,
      activeInputs: serialize(activeInputs),
      activeOutputs: serialize(activeOutputs),
    };
    let rendered;
    try {
      rendered = renderBlock(candidate.typeName, params);
    } catch {
      continue;
    }
    if (rendered.join('\n') === slice.join('\n')) {
      return { typeName: candidate.typeName, params, words: candidate.words };
    }
  }
  return null;
}

function tryMultiBlockPermutationMatch(lines, rb, col, totalWords, rowBands) {
  const maxWords = totalWords - col;
  if (maxWords < 2) return null;

  for (let words = maxWords; words >= 2; words--) {
    for (const borders of ['visible', 'invisible']) {
      const row0 = lines[rb * ROW_HEIGHT].substr(col * WORD_WIDTH, words * WORD_WIDTH);
      const activeInputs = extractActiveIndices(row0, words, 'v', borders === 'visible' ? borderBackground : blankBackground);
      if (!activeInputs || activeInputs.length < 2) continue;

      for (let spanBands = 1; rb + spanBands <= rowBands; spanBands++) {
        const totalLines = spanBands * ROW_HEIGHT;
        const absBlock = [];
        for (let i = 0; i < totalLines; i++) absBlock.push(lines[rb * ROW_HEIGHT + i].substr(col * WORD_WIDTH, words * WORD_WIDTH));

        const activeOutputs = extractActiveIndices(absBlock[totalLines - 1], words, '|', blankBackground);
        if (!activeOutputs || activeOutputs.length !== activeInputs.length) continue;

        // Bordered mode closes its box one row above the terminator (see
        // blockCatalog.js's permutationLayout) -- that row is excluded from
        // content parsing, and must itself be a plain border row.
        const contentEnd = borders === 'visible' ? totalLines - 2 : totalLines - 1;
        if (borders === 'visible' && !isPlainBorderRow(absBlock[totalLines - 2], words * WORD_WIDTH)) continue;

        const middleLines = absBlock.slice(1, contentEnd).map((line) => {
          if (borders !== 'visible') return line;
          const chars = line.split('');
          chars[1] = ' ';
          chars[words * WORD_WIDTH - 2] = ' ';
          return chars.join('');
        });
        const perm = parsePermutationContent(middleLines, activeInputs, activeOutputs);
        if (!perm) continue;

        const params = {
          permutation: perm.join(','),
          words: String(words),
          activeInputs: activeInputs.join(','),
          activeOutputs: activeOutputs.join(','),
          borders,
        };
        let rendered;
        try {
          rendered = renderBlock('multiblockpermutation', params);
        } catch {
          continue;
        }
        if (rendered.join('\n') === absBlock.join('\n')) {
          return { typeName: 'multiblockpermutation', params, words };
        }
      }
    }
  }
  return null;
}

// Shared by decodeGrid (stop at the first problem) and validateAsciiArt
// (collect every problem, for upload validation): walks every row-band/
// column, placing whatever it recognizes and calling `onUnrecognized(rb,
// col, excerptLines)` for whatever it doesn't -- the caller decides whether
// that's fatal. Always advances at least one column past an unrecognized
// cell so a single bad spot doesn't stop the rest of the file from being
// scanned. `pendingAmbiguous` is an out-array: whenever a cell's text
// matches more than one candidate's identical signature (see
// resolveAmbiguousDirections above), the first candidate is placed as a
// provisional guess and `{ block, options }` is pushed here so the caller
// can resolve it once the whole grid -- and thus its connectivity -- is
// known.
function scanGrid(lines, onUnrecognized, pendingAmbiguous) {
  const annotatedLines = lines;
  const bindings = [];
  const typedBoxes = [];
  lines = lines.map((line, index) => {
    if (index % ROW_HEIGHT === 2) {
      const chars=[...line];
      for(let col=0;col<line.length/WORD_WIDTH;col++) {
        const start=col*WORD_WIDTH;
        if(chars[start+1]==='('&&chars[start+WORD_WIDTH-2]===')') {
          typedBoxes.push({row:Math.floor(index/ROW_HEIGHT),col});
          chars[start+1]='[';chars[start+WORD_WIDTH-2]=']';
        }
      }
      return chars.join('');
    }
    if (index % ROW_HEIGHT !== 1) return line;
    return line.replace(/@[0-9]+/g,(marker,offset)=> {
      bindings.push({row:Math.floor(index/ROW_HEIGHT),col:Math.floor(offset/WORD_WIDTH),order:marker.slice(1)});
      return ' '.repeat(marker.length);
    });
  });
  const lineWidth = lines[0].length;
  const totalWords = lineWidth / WORD_WIDTH;
  const rowBands = lines.length / ROW_HEIGHT;
  // Catalog-width components and I/O have an underscore frame. The longest
  // uninterrupted frame (connector glyphs allowed) bounds their width; open
  // wiring/permutation spans are recognized separately. Do not generate wide
  // box templates merely because many independent lanes share one diagram.
  const frameWidths = new Set([1]);
  for (const line of lines) for (const match of line.matchAll(/[_v]+/g)) {
    if (match[0].includes('_')) frameWidths.add(Math.min(totalWords, Math.ceil((match[0].length + 4) / WORD_WIDTH)));
  }
  const maxFrameWords = Math.max(...frameWidths);
  const cellList = [...frameWidths].sort((a,b)=>b-a).flatMap(candidatesAtWidth);
  // Non-merged outputs consist of adjacent independent boxes, so their
  // record width can exceed every uninterrupted frame. Preserve widest-match
  // record granularity without generating wide component templates.
  if (totalWords > 1) {
    for (const params of allParamCombos('output')) {
      if (params.merged !== false) continue;
      for (let words = 1; words <= totalWords; words++) {
        if (frameWidths.has(words)) continue;
        const resolvedParams = { ...params, words };
        cellList.push({ typeName: 'output', params: resolvedParams, words, rendered: renderBlock('output', resolvedParams).join('\n') });
      }
    }
  }
  cellList.sort((a, b) => b.words - a.words);
  const blank = ' '.repeat(WORD_WIDTH);

  // Indexes cellList by words then by its own exact rendered text, so a
  // per-cell lookup is a handful of O(1) Map gets instead of a linear scan
  // over the whole (possibly tens-of-thousands-of-entries-wide, see
  // candidates()'s own scaling) list -- confirmed via direct profiling to
  // matter: a wide real synthesized diagram made the old cellList.find()
  // scan the dominant cost behind an actual OOM (see
  // webapp/tools/verify-library-format.mjs). Preserves cellList's own
  // "widest words wins" tie-break exactly: descendingWidths lists only the
  // widths some candidate actually has, so the lookup loop below still
  // tries the same widths in the same descending order .find() implicitly
  // did, just without wasting work on widths nothing renders as. Preserves
  // tied-options order too: each bucket array is built by iterating
  // cellList in its own original (already words-descending, then
  // type-declaration) order, so bucket[0] is always the same entry
  // cellList.find() would have returned first.
  const byWords = new Map(); // words -> Map<renderedText, candidateEntry[]>
  for (const c of cellList) {
    if (!byWords.has(c.words)) byWords.set(c.words, new Map());
    const byRendered = byWords.get(c.words);
    if (!byRendered.has(c.rendered)) byRendered.set(c.rendered, []);
    byRendered.get(c.rendered).push(c);
  }
  const descendingWidths = [...byWords.keys()].sort((a, b) => b - a);
  // A full match must also match its first word. This exact prefix index
  // retains widest-match precedence without trying every wide output record
  // at each scalar wire cell in large sparse drawings.
  const prefixWidths=new Map();
  for(const candidate of cellList) {
    const prefix=candidate.rendered.split('\n').map(line=>line.slice(0,WORD_WIDTH)).join('\n');
    if(!prefixWidths.has(prefix))prefixWidths.set(prefix,new Set());
    prefixWidths.get(prefix).add(candidate.words);
  }

  const grid = new Grid();
  for (let rb = 0; rb < rowBands; rb++) {
    // No case tolerance: 'v' (lowercase) is the one canonical top-connector
    // glyph (row 0 for components/wiring, row 1 for IO's border-with-
    // connector row) -- an uppercase 'V' or any other spelling is a real
    // mismatch and reported as such, not silently accepted.
    const bandLines = lines.slice(rb * ROW_HEIGHT, rb * ROW_HEIGHT + ROW_HEIGHT);
    let col = 0;
    while (col < totalWords) {
      if (grid.getBlockAt(rb, col)) {
        col += 1;
        continue;
      }
      const firstWord=bandLines.map(line=>line.substr(col*WORD_WIDTH,WORD_WIDTH));
      if(firstWord.every(line=>!line.trim())) {col++;continue;}

      // Extracted once at the widest width that could possibly fit here,
      // not once per candidate width tried below -- re-substr-ing from the
      // full original line for every one of up to totalWords-col candidate
      // widths (descending) made this the dominant remaining cost on a
      // wide diagram (confirmed via direct profiling: still ~20s for a
      // 20-row/175-column slice after the byWords indexing above).
      // Trimming a already-extracted string's own prefix per width via
      // .slice(0, w) is far cheaper than re-extracting from the original.
      let tied = null;
      const maxFit = totalWords - col;
      const widest = bandLines.map((l) => l.substr(col * WORD_WIDTH, maxFit * WORD_WIDTH));
      const eligible=prefixWidths.get(firstWord.join('\n'));
      for (const words of descendingWidths) {
        if(!eligible?.has(words))continue;
        if (words > maxFit) continue;
        const w = words * WORD_WIDTH;
        const slice = widest.map((s) => s.slice(0, w)).join('\n');
        const bucket = byWords.get(words).get(slice);
        if (bucket) { tied = bucket; break; }
      }

      if (tied) {
        const block = grid.placeBlock(rb, col, tied[0].typeName, tied[0].params);
        if (tied.length > 1 && tiedOptionsHaveDistinctPorts(tied)) pendingAmbiguous.push({ block, options: tied });
        col += tied[0].words;
        continue;
      }

      const boxEnd = Math.min(totalWords, col + maxFrameWords);
      const dynamicMatch = tryDynamicLabelMatch(bandLines, col, boxEnd);
      if (dynamicMatch) {
        grid.placeBlock(rb, col, dynamicMatch.typeName, dynamicMatch.params);
        col += dynamicMatch.words;
        continue;
      }

      const freeTextMatch = tryFreeTextMatch(bandLines, col, boxEnd);
      if (freeTextMatch) {
        grid.placeBlock(rb, col, freeTextMatch.typeName, freeTextMatch.params);
        col += freeTextMatch.words;
        continue;
      }

      const coreMatch = tryFixedLabelCoreMatch(bandLines, col, totalWords);
      if (coreMatch) {
        grid.placeBlock(rb, col, coreMatch.typeName, coreMatch.params);
        col += coreMatch.words;
        continue;
      }

      const partialComponentMatch = tryPartialComponentMatch(bandLines, col, boxEnd, cellList);
      if (partialComponentMatch) {
        grid.placeBlock(rb, col, partialComponentMatch.typeName, partialComponentMatch.params);
        col += partialComponentMatch.words;
        continue;
      }

      const permMatch = tryMultiBlockPermutationMatch(lines, rb, col, totalWords, rowBands);
      if (permMatch) {
        grid.placeBlock(rb, col, permMatch.typeName, permMatch.params);
        col += permMatch.words;
        continue;
      }

      const partialIoMatch = tryPartialIoMatch(bandLines, col, boxEnd);
      if (partialIoMatch) {
        grid.placeBlock(rb, col, partialIoMatch.typeName, partialIoMatch.params);
        col += partialIoMatch.words;
        continue;
      }

      const swapMatch = tryPartialSwapMatch(bandLines, col, totalWords);
      if (swapMatch) {
        grid.placeBlock(rb, col, swapMatch.typeName, swapMatch.params);
        col += swapMatch.words;
        continue;
      }

      // Last resort, not hoisted earlier: several matchers above
      // (tryMultiBlockPermutationMatch, tryPartialIoMatch,
      // tryPartialSwapMatch, tryPartialComponentMatch) recognize a WIDE
      // span that can legitimately start at a spacer/inactive word --
      // this cell's own 1-word slice being blank does NOT mean none of
      // them could match starting here. Confirmed by direct construction,
      // not assumed: an earlier version of this check ran right after
      // cellList and broke two real corpus shapes --
      // chacha_quarterround's multiblockpermutation (activeInputs/
      // activeOutputs excluding word 0) and swap[words=4,activeWords=1,2]
      // (word 0 is a pure spacer) -- both have a genuinely blank word 0
      // at the true start of a real, wider block.
      if (bandLines.every((l) => l.substr(col * WORD_WIDTH, WORD_WIDTH) === blank)) {
        col += 1;
        continue;
      }

      onUnrecognized(
        rb,
        col,
        bandLines.map((l) => l.substr(col * WORD_WIDTH, WORD_WIDTH))
      );
      col += 1;
    }
  }
  for (const cell of typedBoxes) {
    const block=grid.getBlockAt(cell.row,cell.col);
    if(!block||block.type!=='free_text'||block.words!==1)throw new Error('Malformed typed operation box');
    const ports=blockPorts(block.type,block.params,0,1);
    block.type='typedbox';block.params.arity=Object.values(ports).filter(p=>p==='in').length;
    const rendered=renderBlock(block.type,block.params);
    if(rendered.some((line,i)=>line!==(i===2?annotatedLines:lines)[cell.row*ROW_HEIGHT+i].slice(cell.col*WORD_WIDTH,(cell.col+1)*WORD_WIDTH)))throw new Error('Malformed typed operation frame');
  }
  for (const binding of bindings) {
    const block = grid.getBlockAt(binding.row,binding.col);
    if (!block || !['xor','and','or','typedbox'].includes(block.type) || block.words!==1) throw new Error('Operand binding has no supported scalar operation');
    if (block.params.operand_order) throw new Error('Duplicate operand binding');
    block.params.operand_order = binding.order;
    const rendered = renderBlock(block.type,block.params);
    if (rendered.some((line,i)=>line!==annotatedLines[block.row*ROW_HEIGHT+i].slice(block.col*WORD_WIDTH,(block.col+block.words)*WORD_WIDTH))) throw new Error('Malformed visible operand binding');
  }
  return grid;
}

function formatUnrecognized(rb, col, excerpt) {
  return `Row ${rb}, col ${col}:\n` + excerpt.map((l) => '  ' + l).join('\n');
}

// Resolves the `pendingAmbiguous` entries scanGrid recorded (each: a
// provisionally-placed block plus the list of same-signature candidates it
// could actually be). Every option in an entry is 1 word wide (only
// `double_wire`/`wire`/`split` collapse this way, and all are always
// words=1), so each entry maps to exactly one grid cell and
// `localWordIndex` is only ever needed for a *neighbor*, never for the
// ambiguous block itself.
//
// This is constraint propagation, not a one-shot lookup: an ambiguous
// block's neighbor may itself be ambiguous (e.g. two invisible crosses back
// to back), so a side that touches another still-unresolved node yields no
// information yet. Each pass around the node list narrows some nodes down
// using whatever's already fixed (real blocks, or ambiguous nodes already
// narrowed to one option by an earlier pass); narrowing any node can free up
// its own neighbors, so this loops to a fixpoint -- exactly the "recursive,
// through connected blocks, until a block with a clear direction is found"
// trace, just expressed as iterative worklist propagation instead of
// recursion. A node whose surviving option set is ever driven to zero is a
// contradiction; one that's still >1 option at fixpoint had no path to any
// unambiguous anchor at all -- both are reported as errors rather than
// guessed.
function resolveAmbiguousDirections(grid, pending) {
  if (pending.length === 0) return [];

  const nodes = new Map(); // "row,col" -> { block, options: [{typeName, params, ports}], live: [surviving option indices] }
  for (const { block, options } of pending) {
    const resolvedOptions = options.map((opt) => ({
      typeName: opt.typeName,
      params: opt.params,
      ports: blockPorts(opt.typeName, opt.params, 0, 1),
    }));
    nodes.set(Grid.key(block.row, block.col), { block, options: resolvedOptions, live: resolvedOptions.map((_, i) => i) });
  }

  // What does the block at (row, col) present on `side`, as seen from an
  // ambiguous node sitting on the other side of it? 'fixed' means known for
  // sure (either a real decoded block, or an ambiguous node already narrowed
  // to a single option); 'pending' means an ambiguous node not yet resolved;
  // 'none' means there's nothing there at all (a dangling port, already a
  // separate error from checkConnectivity -- not this function's concern).
  function neighborPorts(row, col, side) {
    const [dRow, dCol] = NEIGHBOR_OFFSET[side];
    const nRow = row + dRow;
    const nCol = col + dCol;
    const pendingNode = nodes.get(Grid.key(nRow, nCol));
    if (pendingNode) {
      return pendingNode.live.length === 1 ? { kind: 'fixed', ports: pendingNode.options[pendingNode.live[0]].ports } : { kind: 'pending' };
    }
    const neighbor = grid.getBlockAt(nRow, nCol);
    if (!neighbor || neighbor.raw) return { kind: 'none' };
    const facingSide = OPPOSITE_SIDE[side];
    const wordIndex = localWordIndex(neighbor, facingSide, nRow, nCol);
    return { kind: 'fixed', ports: blockPorts(neighbor.type, neighbor.params, wordIndex, neighbor.words) };
  }

  let progress = true;
  while (progress) {
    progress = false;
    for (const node of nodes.values()) {
      if (node.live.length <= 1) continue;
      const { row, col } = node.block;
      const start = node.live; // fixed snapshot for this pass -- see below
      let survivors = start;
      for (const side of ['top', 'bottom', 'left', 'right']) {
        // A side only carries information if it's actually where this
        // node's candidates disagree -- e.g. cross's top/bottom ports are
        // identical for both `mirrored` values, so checking the top/bottom
        // neighbor can never help (or hurt) here, only left/right can. This
        // must be judged against `start`, not the `survivors` an earlier
        // side in this same pass may have already narrowed -- otherwise an
        // earlier side pinning the node to one option would make a later
        // side's now-single-valued port look non-diagnostic and skip a
        // check that could have caught a genuine contradiction between the
        // two neighbors.
        const portValues = new Set(start.map((i) => node.options[i].ports[side]));
        if (portValues.size <= 1) continue;

        const info = neighborPorts(row, col, side);
        if (info.kind !== 'fixed') continue;
        const expected = info.ports[OPPOSITE_SIDE[side]];
        if (expected === undefined) continue; // neighbor doesn't actually connect back on this axis

        survivors = survivors.filter((i) => {
          const v = node.options[i].ports[side];
          if (v === undefined) return true; // this option doesn't claim a port here -- not constrained by this side
          return (v === 'in') === (expected === 'out');
        });
      }
      if (survivors.length !== node.live.length) {
        node.live = survivors;
        progress = true; // narrowing this node may narrow its own neighbors next pass
      }
    }
  }

  const errors = [];
  for (const node of nodes.values()) {
    const { row, col } = node.block;
    if (node.live.length === 0) {
      errors.push(
        `Row ${row}, col ${col}: the direction of this ${node.block.type} block is contradicted by its connected neighbors -- no candidate direction is consistent with all of them.`
      );
      continue;
    }
    // More than one option can survive even once the direction is genuinely
    // pinned down -- e.g. split's lb/rb-style directions carry a param
    // (formerly `bottom`) that doesn't affect ports at all, so two param
    // combos can tie on *identical* ports while still differing as raw
    // options. That's not ambiguity, just redundancy: only report an error
    // when the survivors actually disagree on some side's port value.
    const first = node.options[node.live[0]].ports;
    const samePorts = node.live.every((i) => {
      const ports = node.options[i].ports;
      return ['top', 'bottom', 'left', 'right'].every((side) => ports[side] === first[side]);
    });
    if (!samePorts) {
      errors.push(
        `Row ${row}, col ${col}: could not determine the direction of this ${node.block.type} block -- tracing its connected neighbors never reached one with a clear direction.`
      );
    } else {
      const resolved = node.options[node.live[0]];
      node.block.params = { ...resolved.params };
    }
  }
  return errors;
}

export function decodeGrid(text) {
  const lines = normalizeLines(text);
  let firstError = null;
  const pendingAmbiguous = [];
  const grid = scanGrid(
    lines,
    (rb, col, excerpt) => {
      if (!firstError) firstError = formatUnrecognized(rb, col, excerpt);
    },
    pendingAmbiguous
  );
  if (firstError) throw new Error(`Could not recognize the block at ${firstError}`);
  const ambiguityErrors = resolveAmbiguousDirections(grid, pendingAmbiguous);
  if (ambiguityErrors.length > 0) throw new Error(ambiguityErrors[0]);
  return grid;
}

// Like decodeGrid, but never throws and never stops at the first problem:
// collects every unrecognized cell across the whole file so the upload
// feature (see app.js) can show them all at once instead of a
// fix-one-reupload-see-the-next loop. { valid, errors, grid }: `grid` is
// only populated when `valid` is true (an incomplete/partial decode isn't
// something callers should ever load).
export function validateAsciiArt(text) {
  let lines;
  try {
    lines = normalizeLines(text);
  } catch (err) {
    return { valid: false, errors: [err.message], grid: null };
  }
  const errors = [];
  const pendingAmbiguous = [];
  const grid = scanGrid(
    lines,
    (rb, col, excerpt) => {
      errors.push(formatUnrecognized(rb, col, excerpt));
    },
    pendingAmbiguous
  );
  if (errors.length === 0) errors.push(...resolveAmbiguousDirections(grid, pendingAmbiguous));
  return { valid: errors.length === 0, errors, grid: errors.length === 0 ? grid : null };
}
