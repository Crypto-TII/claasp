// "Human-drawing" layout strategy -- an ALTERNATIVE placement+routing engine
// for the pseudocode -> Grid direction, implementing the algorithm the user
// described (2026-09-07) as "how I think when I draw the diagrams by hand".
// It remains a genuinely independent implementation from the ELK fallback
// and its separately validated corpus fixes, but is now selected by the
// shared pseudocode synthesis entry point. It reuses
// only the generic, policy-free infrastructure (Grid, blockCatalog,
// pseudocode.js's own parser/graph-builder and its gridToPseudocode
// extractor, connectivity.js), never the current engine's own placement/
// splits/wiring logic.
//
// ---- Core idea, and why it's structurally different from the current
// engine -------------------------------------------------------------------
// The current engine PRE-COMPUTES a column for every value with a fixed
// formula (outCol + argIndex - trunkIndex), then discovers -- sometimes only
// at wiring time, sometimes not at all until a downstream connectivity check
// -- that two independently-computed columns collide. Three separate
// attempts this session to patch that discovery-and-repair loop (see project
// memory project_input_row_alignment_gap.md) converged on the same ~44-file
// regression set every time: the failure mode is structural, not a handful
// of independently fixable bugs.
//
// This engine never pre-computes a final column via a formula. It walks the
// diagram row by row, top to bottom, and for every value that needs to reach
// a new column, ATTEMPTS to draw a real horizontal wire there and ONLY
// treats it as reachable if that attempt doesn't run through a column some
// OTHER real block already occupies AT THAT ROW -- checked against the
// physical state of the row being built right now, not a static formula's
// blind guess. A value that can't get all the way to its target this row
// just continues at whatever column it reached and tries again on a later
// row (the blocking box is almost always gone by then, since it only
// occupies its own single row); a value that's never going anywhere (e.g. a
// tied-up leaf) just idles in place, forever representable as a plain
// pass-through wire, since nothing else is ever allowed to silently claim an
// occupied column out from under it. Conflicts are avoided BY CONSTRUCTION,
// not detected after the fact.
//
// ---- Column/row model: slots, not integers --------------------------------
// A column is a `Slot` object (identity only -- see makeSlot), not a raw
// index. Every value's "current column" is a reference to one of these
// objects. Inserting a new column anywhere (the user's own step 6: "if all
// attempts fail, add a row or column") is a plain array splice on the
// ordered `columns` list -- every existing reference to every OTHER slot
// stays perfectly valid, since nothing anywhere stores a raw integer column
// until the very final render pass. Rows work the same way (`rows`, each
// holding a Map<columnSlot, CellSpec>), so inserting a breathing-room row is
// equally cheap and equally safe.
import { BLOCK_TYPES } from '../../../blockCatalog.js';

function makeSlot(label) {
  return { label };
}

// ---- graph analysis --------------------------------------------------------

function unwrapReal(node) {
  while (node.kind === 'named' || node.kind === 'index') {
    node = node.kind === 'named' ? node.inner : node.of;
  }
  return node;
}

// Builds the real-node args-of graph (mirrors placement.js's own `expand`,
// reimplemented independently here per this file's own header -- this
// engine never imports from the current engine's own placement.js/splits.js/
// wiring.js). Returns { argsOf, visitOrder, consumersOf }, where
// `consumersOf` maps every real node to the list of (consumer, argIndex)
// pairs reading it directly -- consumersOf.get(x).length > 1 is exactly the
// user's own "split point" trigger (one split per EXTRA consumer).
export function analyzeGraph(targetOrder) {
  const argsOf = new Map();
  const visitOrder = [];
  const seen = new Set();
  const consumersOf = new Map();

  function addConsumer(node, consumer, argIndex) {
    if (!consumersOf.has(node)) consumersOf.set(node, []);
    consumersOf.get(node).push({ consumer, argIndex });
  }

  function expand(node) {
    const real = unwrapReal(node);
    if (seen.has(real)) return real;
    seen.add(real);
    visitOrder.push(real);
    if (real.kind === 'call') {
      const kids = real.args.map(unwrapReal);
      argsOf.set(real, kids);
      real.args.forEach((raw, i) => {
        expand(raw);
        addConsumer(unwrapReal(raw), real, i);
      });
    } else {
      argsOf.set(real, []);
    }
    return real;
  }

  const targetRoots = targetOrder.map((t) => ({ t, real: expand(t.node) }));
  return { argsOf, visitOrder, consumersOf, targetRoots };
}

// True for a call this engine draws as one wide "merged group" box (Mode C)
// -- same narrow, best-effort scope as the current engine's own isGroupNode
// (splits.js): only recognizes the shape, doesn't attempt real crossing-arc
// routing for it. Group calls are out of scope for this engine's own first
// working version -- flagged, not silently mishandled (see synthesize's own
// guard).
function isGroupCall(node) {
  if (node.kind !== 'call' || node.args.length <= 1) return false;
  const type = BLOCK_TYPES[node.typeName];
  return type?.inputs === 1 && type.params.some((param) => param.name === 'words');
}

// ---- row assignment ---------------------------------------------------
// Every leaf sits at row 0 and every output's own tap sits at the LAST row,
// unconditionally -- this is the confirmed corpus convention (see project
// memory project_input_row_alignment_gap.md: verified directly against
// chacha_half_quarterround.asciiart and even_mansour_single_sbox[rounds=2,
// key=double].asciiart, both of which draw EVERY input on their own first
// row and EVERY output on their own last row, regardless of how deep each
// one's own real use is). Everything in between uses the same longest-path-
// to-nearest-output depth metric the current engine already validates
// (row = maxDepth - depth(node)), just clamped at both ends instead of
// governing leaves too -- this engine's own row-by-row wiring walk (not a
// fixed per-node formula) is what makes leaving a leaf's own real use many
// rows below it safe, unlike the current engine's own attempt at the exact
// same clamp (see project_input_row_alignment_gap.md's own three reverted
// attempts).
function computeDepthToOutput(outputRoots, argsOf) {
  const order = [];
  const visited = new Set();
  function postorder(node) {
    if (visited.has(node)) return;
    visited.add(node);
    for (const a of argsOf.get(node) || []) postorder(a);
    order.push(node);
  }
  for (const root of outputRoots) postorder(root);
  const d = new Map();
  for (const root of outputRoots) d.set(root, Math.max(d.get(root) ?? 0, 0));
  for (const node of order.slice().reverse()) {
    const nd = d.get(node) ?? 0;
    for (const arg of argsOf.get(node) || []) {
      const cand = nd + 1;
      if (cand > (d.get(arg) ?? 0)) d.set(arg, cand);
    }
  }
  return d;
}

export function computeRows(targetRoots, argsOf, outputRoots) {
  const d = computeDepthToOutput(outputRoots, argsOf);
  for (const { real } of targetRoots) {
    if (!d.has(real)) d.set(real, 0); // dead-code fallback, same spirit as placement.js's own island seeding
  }
  let maxD = 0;
  for (const v of d.values()) maxD = Math.max(maxD, v);
  const rowOf = new Map();
  for (const [node, dist] of d) rowOf.set(node, maxD - dist);
  for (const [node] of d) {
    if (node.kind === 'input') rowOf.set(node, 0);
  }
  return { rowOf, maxRow: maxD };
}

// A "words a, b = 2" output declaration whose two targets are BARE
// references to two sibling leaves of ANOTHER "words c, d = 2" input
// declaration, crossed (the output declared first reads the input declared
// SECOND, and vice versa), is a genuine swap -- e.g. swap_permutation's own
// `output[1] = input[2]; output[2] = input[1]`. Left as plain leaf taps,
// this engine's own general column-alignment routing has no way to
// represent it: two values trading columns in the same cell needs a real
// TURNING double_wire (`top_to_left+right_to_bottom`, see blockCatalog.js),
// not the STRAIGHT crossing (`top_to_bottom+left_to_right`) a value merely
// passing through an unrelated live column produces -- structurally
// different shapes, not a rendering nuance. Detected and rewritten here,
// mirroring (independently -- see this file's own header) the same
// technique the current engine's placement.js uses for the identical
// pattern via its own detectSwapPairs: rewrite the pair into a synthetic
// 2-argument `swap` call node, then let the ordinary "any 2-arg call"
// machinery place and wire it like anything else.
function countLeafUses(targetOrder) {
  const uses = new Map();
  const seenCalls = new Set();
  function visit(node) {
    if (node.kind === 'named') return visit(node.inner);
    if (node.kind === 'index') return visit(node.of);
    if (node.kind === 'input') {
      uses.set(node, (uses.get(node) || 0) + 1);
      return;
    }
    if (seenCalls.has(node)) return;
    seenCalls.add(node);
    for (const a of node.args) visit(a);
  }
  for (const t of targetOrder) visit(t.node);
  return uses;
}

export function detectSwapPairs(targetOrder) {
  const uses = countLeafUses(targetOrder);
  const outputsByGroup = new Map();
  for (const t of targetOrder) {
    if (!t.isOutput || !t.wordGroup) continue;
    if (!outputsByGroup.has(t.wordGroup.groupId)) outputsByGroup.set(t.wordGroup.groupId, []);
    outputsByGroup.get(t.wordGroup.groupId).push(t);
  }
  for (const group of outputsByGroup.values()) {
    if (group.length !== 2) continue;
    const [a, b] = group.sort((x, y) => x.wordGroup.index - y.wordGroup.index);
    if (a.node.kind !== 'input' || b.node.kind !== 'input') continue;
    const wgA = a.node.wordGroup;
    const wgB = b.node.wordGroup;
    if (!wgA || !wgB || wgA.groupId !== wgB.groupId || wgA.total !== 2) continue;
    if (!(wgA.index === 1 && wgB.index === 0)) continue; // the only non-identity permutation of 2
    if ((uses.get(a.node) || 0) !== 1 || (uses.get(b.node) || 0) !== 1) continue;

    const leaf0 = b.node;
    const leaf1 = a.node;
    const swapNode = { kind: 'call', typeName: 'swap', params: {}, args: [leaf0, leaf1] };
    a.node = { kind: 'index', of: swapNode, index: 1 };
    b.node = { kind: 'index', of: swapNode, index: 2 };
  }
  return targetOrder;
}

export { unwrapReal, isGroupCall };
