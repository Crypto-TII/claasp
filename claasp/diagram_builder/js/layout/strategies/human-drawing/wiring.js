// Phase 2 of the human-drawing engine: row-by-row grid construction. See
// engine.js's own header for the full design rationale (slot-based columns,
// attempt-then-check-then-grow routing, developed independently of the
// current engine per project memory project_human_drawing_layout_strategy_
// proposal.md). This file owns the row-by-row simulation and slot ->
// Grid materialization; engine.js owns pure graph analysis (argsOf/
// consumersOf/rowOf).
//
// Built up incrementally, each stage validated against a real corpus file
// before the next is added -- see this directory's own README for current
// status and the exact scope guards below for what's deliberately not
// handled yet (multi-arg convergence, 2+ extra consumers, dynamic column
// growth under a genuine conflict).
import { Grid } from '../../../grid.js';
import { defaultParams } from '../../../blockCatalog.js';
import { analyzeGraph, computeRows, unwrapReal, isGroupCall } from './engine.js';

function makeSlot(label) {
  return { label };
}

function naturalNameOrder(a, b) {
  return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
}

// Ordered list of column slots -- see engine.js's own header for why a slot
// (identity only) rather than a raw integer is what makes column growth
// safe. `insertNear` is the only way a new column is ever created once
// fan-out needs one: always immediately adjacent to a real anchor, never a
// bare `append`, so a fork's own hop to it is always exactly one step (v0
// scope: see the README on why a longer walk isn't implemented yet).
class ColumnSpace {
  constructor() {
    this.slots = [];
  }
  indexOf(slot) {
    return this.slots.indexOf(slot);
  }
  insertNear(anchor, dir, label) {
    const slot = makeSlot(label);
    const i = this.indexOf(anchor);
    this.slots.splice(dir < 0 ? i : i + 1, 0, slot);
    return slot;
  }
}

export function buildGrid(targetOrder, options = {}) {
  const { splitDirection = 'mixed' } = options;
  const { argsOf, visitOrder, consumersOf, targetRoots } = analyzeGraph(targetOrder);
  const outputTargets = targetOrder.filter((t) => t.isOutput).sort(naturalNameOrder);
  const outputRoots = outputTargets.map((t) => unwrapReal(t.node));
  const { rowOf, maxRow } = computeRows(targetRoots, argsOf, outputRoots);

  const isSwap = (node) => node.kind === 'call' && node.typeName === 'swap';
  const isCommutative = (node) => node.kind === 'call' && ['xor', 'and', 'or'].includes(node.typeName);

  // Whether a value's dependency cone contains public and/or secret inputs.
  // This is deliberately primitive-agnostic: it only uses declarations in
  // the pseudocode.  A commutative gate can put any operand on its vertical
  // port without changing the function, so prefer an operand carrying public
  // data over a secret-only side input.  That keeps the main computation on
  // the public/non-secret input line in feed-forward and Even-Mansour shapes.
  const dependencyKinds = new Map();
  function kindsOf(node) {
    node = unwrapReal(node);
    if (dependencyKinds.has(node)) return dependencyKinds.get(node);
    let kinds;
    if (node.kind === 'input') {
      const secret = Boolean(node.secret || node.groupSecret);
      kinds = { hasPublic: !secret, hasSecret: secret };
    } else {
      kinds = { hasPublic: false, hasSecret: false };
      for (const arg of argsOf.get(node) || []) {
        const child = kindsOf(arg);
        kinds.hasPublic ||= child.hasPublic;
        kinds.hasSecret ||= child.hasSecret;
      }
    }
    dependencyKinds.set(node, kinds);
    return kinds;
  }

  for (const node of visitOrder) {
    if (!isSwap(node) && isGroupCall(node)) throw new Error('human-drawing engine: group (Mode C) calls are not supported yet');
  }
  // ---- v0 scope guards, relaxed one at a time as each gets a real test
  // case -- see the README for the full remaining plan.
  for (const [node, consumers] of consumersOf) {
    if (consumers.length > 2) {
      throw new Error(`human-drawing engine (v0): more than one EXTRA consumer not supported yet (${node.kind === 'input' ? node.name : node.typeName} has ${consumers.length})`);
    }
  }

  // ---- columns: one slot per distinct leaf, in first-appearance order
  // (declared-bracket ordering and secret placement deferred to the next
  // stage that actually needs it -- see the README).
  const leaves = visitOrder.filter((n) => n.kind === 'input');
  const columns = new ColumnSpace();
  const colOf = new Map(); // realNode -> its own PRIMARY slot (used by its first/only consumer)
  for (const n of leaves) {
    const slot = makeSlot(n.name);
    columns.slots.push(slot);
    colOf.set(n, slot);
  }

  const grid = new Grid();
  const colValue = new Map(); // Slot -> node currently alive there
  const extraSlotFor = new Map(); // argNode -> Map<consumerNode, Slot> (a non-first consumer's own delivery slot for THAT SPECIFIC argument -- keyed on both, not consumer alone, since a different argument of the SAME consumer must never pick up an unrelated argument's own fork)
  let gridRow = 0;

  function fillGaps(r) {
    for (const slot of colValue.keys()) {
      const c = columns.indexOf(slot);
      if (!grid.getBlockAt(r, c)) grid.placeBlock(r, c, 'wire', { ...defaultParams('wire'), direction: 'top_to_bottom' });
    }
  }

  // Called immediately after `node`'s own value is placed at colOf.get(node)
  // -- marks it alive, and if it has 2+ real consumers, draws a real split
  // (the user's own step 1: one split per EXTRA consumer) as its own
  // dedicated physical row right here, forking a fresh, immediately-
  // adjacent column for every consumer AFTER the first (sorted by the
  // consumer's own row, so whichever needs the value SOONEST gets the
  // no-detour original column and only the later one(s) get carried
  // sideways) -- consumes one extra physical row only when fan-out
  // actually happens, exactly like the current engine's own FanoutRow, but
  // landing on a freshly allocated Slot rather than a formula-computed
  // integer column.
  function produced(node) {
    const homeSlot = colOf.get(node);
    colValue.set(homeSlot, node);
    const consumers = (consumersOf.get(node) || []).slice().sort((a, b) => rowOf.get(a.consumer) - rowOf.get(b.consumer));
    if (consumers.length <= 1) return;
    const dir = splitDirection === 'left' ? -1 : 1;
    const label = node.kind === 'input' ? node.name : node.typeName;
    // Insert FIRST, then read homeSlot's own column -- for dir<0 the new
    // slot is spliced in BEFORE home, shifting home's own array index by
    // one; reading homeCol before insertion (an earlier version of this
    // function did) used a now-stale index and placed the split one column
    // off from the home it was actually forking from.
    const freshSlot = columns.insertNear(homeSlot, dir, `${label}-fork`);
    const homeCol = columns.indexOf(homeSlot);
    if (!extraSlotFor.has(node)) extraSlotFor.set(node, new Map());
    extraSlotFor.get(node).set(consumers[1].consumer, freshSlot);
    const splitDir = dir > 0 ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom';
    grid.placeBlock(gridRow, homeCol, 'split', { ...defaultParams('split'), direction: splitDir });
    const forkCol = columns.indexOf(freshSlot);
    grid.placeBlock(gridRow, forkCol, 'wire', { ...defaultParams('wire'), direction: dir > 0 ? 'left_to_bottom' : 'right_to_bottom' });
    colValue.set(freshSlot, node);
    fillGaps(gridRow);
    gridRow++;
  }

  // Resolves the column a given argument occupies FOR a specific consumer
  // -- a non-first consumer reads its own forked delivery slot instead of
  // the argument's home slot (see `produced` above).
  function argColOf(argNode, consumerNode) {
    const slot = extraSlotFor.get(argNode)?.get(consumerNode) || colOf.get(argNode);
    return columns.indexOf(slot);
  }

  function completeOrderedGroup(seed, items, groupOf, colOfItem, description) {
    const group = groupOf(seed);
    const members = items
      .filter((item) => groupOf(item)?.groupId === group.groupId)
      .sort((a, b) => groupOf(a).index - groupOf(b).index);
    if (members.length !== group.total || members.some((item, index) => groupOf(item).index !== index)) {
      throw new Error(`human-drawing engine: partial ${description} word groups are not supported yet`);
    }
    const cols = members.map(colOfItem);
    if (!cols.every((col, index) => col === cols[0] + index)) {
      throw new Error(`human-drawing engine: non-contiguous ${description} word groups are not supported yet`);
    }
    return { group, members, cols };
  }

  // Row 0: place every leaf, then run fan-out for any leaf with 2+
  // consumers (each gets its own dedicated fork row -- v0 keeps this
  // simple rather than merging multiple leaves' own forks into one row).
  const placedInputGroups = new Set();
  for (const n of leaves) {
    const c = columns.indexOf(colOf.get(n));
    if (!n.wordGroup) {
      grid.placeBlock(gridRow, c, 'input', { ...defaultParams('input'), secrecy: n.secret ? 'secret' : 'public' });
      continue;
    }
    if (placedInputGroups.has(n.wordGroup.groupId)) continue;
    const { group, members, cols } = completeOrderedGroup(
      n,
      leaves,
      (leaf) => leaf.wordGroup,
      (leaf) => columns.indexOf(colOf.get(leaf)),
      'input'
    );
    grid.placeBlock(gridRow, cols[0], 'input', {
      ...defaultParams('input'),
      words: group.total,
      secrecy: members.some((leaf) => leaf.secret || leaf.groupSecret) ? 'secret' : 'public',
    });
    placedInputGroups.add(group.groupId);
  }
  gridRow++;
  for (const n of leaves) produced(n);

  // Rows 1..maxRow: place each 1-arg/swap call directly below its own
  // argument's CURRENT column for THIS specific consumer, then run its own
  // fan-out if it also has 2+ consumers.
  const nodesByRow = new Map();
  for (const node of visitOrder) {
    if (node.kind === 'input') continue;
    const r = rowOf.get(node);
    if (!nodesByRow.has(r)) nodesByRow.set(r, []);
    nodesByRow.get(r).push(node);
  }
  for (let r = 1; r <= maxRow; r++) {
    for (const node of nodesByRow.get(r) || []) {
      const args = argsOf.get(node) || [];
      if (isSwap(node)) {
        // Two ALREADY-adjacent leaves (detectSwapPairs' own precondition --
        // see engine.js) trading columns -- a real mutual exchange needs a
        // TURNING double_wire inside the block itself (blockCatalog.js's
        // own swap family), not this stage's general column-routing, so
        // it's placed directly here rather than through the 1-arg path
        // above.
        const [leaf0, leaf1] = args;
        const c0 = argColOf(leaf0, node);
        const c1 = argColOf(leaf1, node);
        if (c1 !== c0 + 1) {
          throw new Error('human-drawing engine (v0): swap requires its two leaves to already be adjacent columns');
        }
        grid.placeBlock(gridRow, c0, 'swap', { ...defaultParams('swap'), words: 2 });
        colOf.set(node, columns.slots[c0]); // anchor only -- taps resolve their own word via the index below
      } else if (args.length <= 1) {
        const argCol = args.length ? argColOf(args[0], node) : 0;
        const defaults = defaultParams(node.typeName);
        grid.placeBlock(gridRow, argCol, node.typeName, { ...defaults, ...node.params, words: 1 });
        colOf.set(node, columns.slots[argCol]);
      } else {
        // Multi-arg convergence: v0 only handles the case where every
        // argument's OWN current column (its home, or its own forked
        // delivery slot for this specific consumer -- see argColOf) is
        // ALREADY contiguous and strictly increasing with argument index.
        // Round-trip correctness only ever requires that ordering (see
        // engine.js's own header / splits.js's identical convention in the
        // current engine) -- it happens to already hold here whenever a
        // fan-out's own freshly-inserted fork slot (always immediately
        // adjacent to its source, see ColumnSpace.insertNear) lands exactly
        // where a sibling argument already sits, which is exactly
        // feedforward[rounds=1]'s own shape: `input`'s fork for the outer
        // xor lands directly next to `sbox`'s own (unmoved) column. A
        // genuine convergence walk -- bringing non-adjacent arguments
        // together -- is the next stage (see the README); this deliberately
        // throws rather than silently misplacing anything when the
        // arguments aren't already in position.
        const cols = args.map((a) => argColOf(a, node));
        for (let i = 1; i < cols.length; i++) {
          if (cols[i] !== cols[i - 1] + 1) {
            throw new Error(`human-drawing engine (v0): multi-arg convergence not supported yet (${node.typeName}'s own arguments aren't already adjacent)`);
          }
        }
        // A binary commutative component has equivalent left/top argument
        // orders.  Keep the public/computed operand vertical when possible;
        // ties retain source argument order, which also keeps an already-
        // computed first operand on its established trunk.  Three-input
        // components still require the middle column because their physical
        // left/top/right ports straddle the box.
        let verticalIndex = args.length === 2 || args.length === 3 ? 1 : -1;
        if (args.length === 2 && isCommutative(node)) {
          const score = (arg, index) => {
            const kinds = kindsOf(arg);
            return [kinds.hasPublic ? 1 : 0, unwrapReal(arg).kind === 'call' ? 1 : 0, -index];
          };
          const scores = args.map(score);
          const differing = scores[0].findIndex((value, i) => value !== scores[1][i]);
          verticalIndex = differing < 0 || scores[0][differing] > scores[1][differing] ? 0 : 1;
        }
        if (verticalIndex < 0) {
          throw new Error(`human-drawing engine (v0): ${args.length}-argument components are not supported yet`);
        }
        const boxCol = cols[verticalIndex];
        const outCol = boxCol;
        const lateralIndex = args.length === 2 ? 1 - verticalIndex : -1;
        const defaults = defaultParams(node.typeName);
        const params = {
          ...defaults,
          ...node.params,
          ...(node.typeName === 'xor' || node.typeName === 'and' || node.typeName === 'or' ? { inputs: args.length } : {}),
          ...(args.length === 2 ? { side: cols[lateralIndex] < boxCol ? 'left' : 'right' } : {}),
        };
        grid.placeBlock(gridRow, boxCol, node.typeName, params);
        for (let i = 0; i < cols.length; i++) {
          if (i === verticalIndex) continue;
          const lateralCol = cols[i];
          grid.placeBlock(gridRow, lateralCol, 'wire', {
            ...defaultParams('wire'),
            direction: lateralCol < boxCol ? 'top_to_right' : 'top_to_left',
          });
          const consumedSlot = columns.slots[lateralCol];
          colValue.delete(consumedSlot);
        }
        colOf.set(node, columns.slots[outCol]);
      }
    }
    fillGaps(gridRow);
    gridRow++;
    for (const node of nodesByRow.get(r) || []) produced(node);
  }

  // Tap row: every output target gets its own I/O block, one row below its
  // own value's own compute row -- placed here (after every compute row is
  // done) since v0 only ever has outputs at the deepest row.
  //
  // A target reaching a `swap` call via `[index]` (detectSwapPairs' own
  // synthetic wrapper) resolves to ONE SPECIFIC WORD of that call's own
  // 2-word box, not the call as a whole -- generic `unwrapReal` collapses
  // 'index' straight through to the call itself (right for an ordinary
  // multi-word tuple reference, wrong here, since both swap outputs would
  // otherwise collapse onto the exact same anchor column), so this checks
  // for that shape explicitly before falling back to the ordinary path.
  fillGaps(gridRow - 1);
  const placedOutputGroups = new Set();
  function outputColumn(t) {
    const raw = t.node;
    if (raw.kind === 'index' && raw.of.kind === 'call' && isSwap(raw.of)) {
      return columns.indexOf(colOf.get(raw.of)) + (raw.index - 1);
    }
    return columns.indexOf(colOf.get(unwrapReal(raw)));
  }

  for (const t of outputTargets) {
    const c = outputColumn(t);
    if (!t.wordGroup) {
      grid.placeBlock(gridRow, c, 'output', { ...defaultParams('output'), merged: true, id: t.name });
      continue;
    }
    if (placedOutputGroups.has(t.wordGroup.groupId)) continue;
    const { group, cols } = completeOrderedGroup(t, outputTargets, (target) => target.wordGroup, outputColumn, 'output');
    grid.placeBlock(gridRow, cols[0], 'output', {
      ...defaultParams('output'),
      words: group.total,
      // A declaration represents one logical multi-word output group.
      // gridToPseudocode deliberately reconstructs that declaration only
      // from a merged block; merged=false means unrelated adjacent boxes.
      merged: true,
      id: t.name,
    });
    placedOutputGroups.add(group.groupId);
  }

  return grid;
}
