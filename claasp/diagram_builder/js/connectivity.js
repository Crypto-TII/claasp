// Checks whether a grid (see grid.js) is "well connected": every port a
// placed block declares (in or out, on any side) must face a neighboring
// block whose own port on the facing side is the complementary in/out.
// This is independent of rendering (render.js) -- glyphs are drawn from a
// block's own declared ports regardless of what's actually next to it, but
// whether the *diagram* makes sense is exactly this adjacency check.
import { BLOCK_TYPES, blockPorts } from './blockCatalog.js';
import { blockRoutes } from './render.js';

// Exported for decode.js's ambiguous-direction resolver (see its
// resolveAmbiguousDirections), which walks the same block-to-block adjacency
// this file uses, just to narrow down an unknown port instead of validating
// a fixed one.
export const OPPOSITE_SIDE = { top: 'bottom', bottom: 'top', left: 'right', right: 'left' };
export const NEIGHBOR_OFFSET = {
  top: [-1, 0],
  bottom: [1, 0],
  left: [0, -1],
  right: [0, 1],
};

export function localWordIndex(neighbor, side, row, col) {
  if (side === 'top' || side === 'bottom') return col - neighbor.col;
  return row - neighbor.row; // left/right neighbors are always single-row, wordIndex 0
}

export function checkConnectivity(grid) {
  const problems = [];

  for (const block of grid.allBlocks()) {
    if (block.raw) continue; // a decoded library primitive is self-contained, no external ports

    // A cryptographic component (sbox, xor, rotate, ...) with no input at
    // all almost always means its top/left/right port got toggled off by
    // mistake (see blockCatalog.js's componentSidePort override toolbar) --
    // 'constant' is the only catalog type deliberately input-less
    // (inputs: 0), and 'input'/'output'/wiring/multiblockpermutation blocks
    // are a different family entirely, so this can't misfire on any of
    // those legitimate no-input cases.
    if (BLOCK_TYPES[block.type].family === 'component' && block.type !== 'constant' && !(block.type==='typedbox'&&Number(block.params.arity)===0)) {
      const hasInput = Array.from({ length: block.words }, (_, w) => blockPorts(block.type, block.params, w, block.words)).some(
        (ports) => ports.top === 'in' || ports.left === 'in' || ports.right === 'in' || ports.bottom === 'in'
      );
      if (!hasInput) {
        problems.push({
          row: block.row,
          col: block.col,
          side: 'top',
          type: 'no-input',
          message: `${block.type} at [${block.row}, ${block.col}] has no input at all -- only 'input' and 'constant' blocks may have no input`,
        });
      }
    }

    for (let w = 0; w < block.words; w++) {
      const col = block.col + w;
      const ports = blockPorts(block.type, block.params, w, block.words);

      for (const side of ['top', 'bottom', 'left', 'right']) {
        const value = ports[side];
        if (!value) continue;

        // NEIGHBOR_OFFSET.bottom assumes a 1-row block -- multiblockpermutation
        // is the only type whose rowSpan can exceed 1 (see blockRowSpan), so its
        // bottom edge sits rowSpan rows down, not block.row+1.
        const [dRow, dCol] = NEIGHBOR_OFFSET[side];
        const neighborRow = side === 'bottom' ? block.row + block.rowSpan : block.row + dRow;
        const neighbor = grid.getBlockAt(neighborRow, col + dCol);

        if (!neighbor) {
          problems.push({
            row: block.row,
            col,
            side,
            type: value === 'in' ? 'missing-input' : 'dangling-output',
            message: `${block.type} at [${block.row}, ${col}] has a ${value === 'in' ? 'missing input' : 'dangling output'} on its ${side} side`,
          });
          continue;
        }

        const facingSide = OPPOSITE_SIDE[side];
        const neighborWordIndex = localWordIndex(neighbor, facingSide, neighborRow, col + dCol);
        const neighborPorts = blockPorts(neighbor.type, neighbor.params, neighborWordIndex, neighbor.words);
        const neighborValue = neighborPorts[facingSide];
        const expected = value === 'in' ? 'out' : 'in';

        if (neighborValue !== expected) {
          problems.push({
            row: block.row,
            col,
            side,
            type: 'mismatched-connector',
            message: `${block.type} at [${block.row}, ${col}] expects ${expected === 'in' ? 'an input' : 'an output'} from its ${side} neighbor, but ${neighbor.type} at [${neighbor.row}, ${neighbor.col}] doesn't provide one`,
          });
        }
      }
    }
  }

  return {
    wellConnected: problems.length === 0 && !grid.isEmpty(),
    problems,
  };
}

// Traces which parts of a block's rendered output are *solely* dependent on
// secret inputs -- i.e. every leaf source reachable by walking backward is
// a secret-marked `input` block, with no public input or `constant`
// contributing anywhere along the way (a `constant` is a known, fixed
// value, so mixing it in disqualifies a value from being "solely" secret,
// same as mixing in a public input). Used by app.js to highlight the
// Preview pane and the grid editor's diagram view -- an entirely different
// question from checkConnectivity's local port-adjacency check above, since
// this one traces actual dataflow through the whole DAG.
//
// Traced per *route*, not per whole block -- see render.js's blockRoutes for
// why: a handful of wiring-ish types (double_wire, swap,
// multiblockpermutation) draw two or more independent paths through the
// same box that never actually connect (e.g. a double_wire's vertical and
// horizontal lines visually cross but don't mix), so a secret top input and
// a public left input on the same double_wire must be traced -- and
// highlighted -- independently rather than conflating the whole block into
// one taint value. Every other block type has exactly one route covering its entire
// rendered area, so this reduces to the original whole-block behavior for
// them automatically.
//
// Returns a Map from "row,col" (a block's own anchor key) to a Set of
// tainted route indices (indexing into blockRoutes(block.type,
// block.params).routes) -- combine with that same blockRoutes() call to
// find out exactly which characters (route.cells) to highlight.
export function computeSecretTaint(grid) {
  const taintedRoutes = new Map();
  const memo = new Map(); // "row,col,routeIndex" -> boolean
  const visiting = new Set();
  const keyOf = (b) => `${b.row},${b.col}`;

  const isSecretInput = (b) => BLOCK_TYPES[b.type].family === 'io' && BLOCK_TYPES[b.type].kind === 'input' && b.params.secrecy === 'secret';
  const isLeaf = (b) => (BLOCK_TYPES[b.type].family === 'io' && BLOCK_TYPES[b.type].kind === 'input') || (BLOCK_TYPES[b.type].family === 'component' && (b.type === 'constant'||(b.type==='typedbox'&&Number(b.params.arity)===0)));

  const markTainted = (block, routeIndex) => {
    const key = keyOf(block);
    if (!taintedRoutes.has(key)) taintedRoutes.set(key, new Set());
    taintedRoutes.get(key).add(routeIndex);
  };

  // Is the value neighbor provides on its `side` port at physical word
  // column `col` secret? Either neighbor is a leaf (input/constant), or we
  // find which of its routes actually produces that output and trace it.
  function taintAtPort(neighbor, side, col) {
    if (isLeaf(neighbor)) return isSecretInput(neighbor);
    const wordOffset = col - neighbor.col;
    const { routes } = blockRoutes(neighbor.type, neighbor.params);
    const routeIndex = routes.findIndex((r) => r.outs.some((o) => o.side === side && o.wordOffset === wordOffset));
    if (routeIndex < 0) return false; // no route produces this output -- shouldn't normally happen for a real port, treat conservatively as not-secret
    return routeTaint(neighbor, routeIndex);
  }

  function routeTaint(block, routeIndex) {
    const key = `${keyOf(block)},${routeIndex}`;
    if (memo.has(key)) return memo.get(key);
    if (visiting.has(key)) return false; // cycle guard -- inconclusive, treat as not-tainted
    visiting.add(key);

    const { routes } = blockRoutes(block.type, block.params);
    const route = routes[routeIndex];
    let result = false;
    if (route.into.length > 0) {
      result = route.into.every(({ side, wordOffset }) => {
        const col = block.col + wordOffset;
        const [dRow, dCol] = NEIGHBOR_OFFSET[side];
        const neighbor = grid.getBlockAt(block.row + dRow, col + dCol);
        if (!neighbor) return false;
        const facingSide = OPPOSITE_SIDE[side];
        const neighborWordIndex = localWordIndex(neighbor, facingSide, block.row + dRow, col + dCol);
        return taintAtPort(neighbor, facingSide, neighbor.col + neighborWordIndex);
      });
    }

    visiting.delete(key);
    memo.set(key, result);
    if (result) markTainted(block, routeIndex);
    return result;
  }

  for (const block of grid.allBlocks()) {
    if (block.raw) continue;
    if (isLeaf(block)) {
      if (isSecretInput(block)) markTainted(block, 0); // matches defaultRoutes' single-route (index 0) convention
      continue;
    }
    const { routes } = blockRoutes(block.type, block.params);
    routes.forEach((_, idx) => routeTaint(block, idx));
  }

  return taintedRoutes;
}
