// Sparse [row, col] grid of placed blocks. [0, 0] is the top-left, matching
// the coordinate convention requested for the editor. Columns are counted in
// word-units (11-char slots); a block occupies col..col+words-1 in its row.
// Most blocks are one row tall (rowSpan 1), but a decoded library primitive
// (see decode.js) can span several rows -- rowSpan lets a block reserve a
// taller rectangle of cells.
import { blockWords, blockRowSpan, defaultIdFor } from './blockCatalog.js';

export class Grid {
  constructor() {
    // key "row,col" -> block; only the block's own top-left cell is a key,
    // but every cell it covers is indexed via #occupied for fast lookups.
    this.blocks = new Map();
    this.occupied = new Map(); // "row,col" -> top-left "row,col" key
  }

  static key(row, col) {
    return `${row},${col}`;
  }

  footprint(typeName, params) {
    return { words: blockWords(typeName, params), rowSpan: blockRowSpan(typeName, params) };
  }

  canPlaceFootprint(row, col, words, rowSpan, ignoreKeys = null) {
    if (row < 0 || col < 0) return false;
    for (let dr = 0; dr < rowSpan; dr++) {
      for (let dc = 0; dc < words; dc++) {
        const occupant = this.occupied.get(Grid.key(row + dr, col + dc));
        if (occupant && !(ignoreKeys && ignoreKeys.has(occupant))) return false;
      }
    }
    return true;
  }

  canPlace(row, col, typeName, params) {
    const { words, rowSpan } = this.footprint(typeName, params);
    return this.canPlaceFootprint(row, col, words, rowSpan);
  }

  #insert(row, col, words, rowSpan, block) {
    const key = Grid.key(row, col);
    this.blocks.set(key, block);
    for (let dr = 0; dr < rowSpan; dr++) {
      for (let dc = 0; dc < words; dc++) this.occupied.set(Grid.key(row + dr, col + dc), key);
    }
    return block;
  }

  // A block that arrives with no `id` of its own (the common case: hand
  // placed via the editor, or via gridFormula.js) gets one right here,
  // from its own now-known position -- see blockCatalog.js's
  // defaultIdFor. Pseudocode-synthesized blocks (pseudocodeLayout.js)
  // set `params.id` explicitly beforehand instead, so this is a no-op
  // for those.
  placeBlock(row, col, typeName, params) {
    const { words, rowSpan } = this.footprint(typeName, params);
    if (!this.canPlaceFootprint(row, col, words, rowSpan)) {
      throw new Error(`Cannot place ${typeName} at [${row}, ${col}]: overlaps an existing block`);
    }
    const finalParams = { ...params };
    if (!finalParams.id) finalParams.id = defaultIdFor(typeName, row, col);
    const block = { row, col, words, rowSpan, type: typeName, params: finalParams, raw: false };
    return this.#insert(row, col, words, rowSpan, block);
  }

  // A pre-rendered, non-decomposed chunk of ASCII (see decode.js's fallback
  // path): `lines` is its full text (words*11 chars per line, rowSpan*5
  // lines total), rendered as-is with no per-block port checking.
  placeRawBlock(row, col, { label, lines, words, rowSpan }) {
    if (!this.canPlaceFootprint(row, col, words, rowSpan)) {
      throw new Error(`Cannot place "${label}" at [${row}, ${col}]: overlaps an existing block`);
    }
    const block = { row, col, words, rowSpan, type: label, params: {}, raw: true, lines };
    return this.#insert(row, col, words, rowSpan, block);
  }

  removeBlock(row, col) {
    const key = this.occupied.get(Grid.key(row, col));
    if (!key) return false;
    const block = this.blocks.get(key);
    for (let dr = 0; dr < block.rowSpan; dr++) {
      for (let dc = 0; dc < block.words; dc++) this.occupied.delete(Grid.key(block.row + dr, block.col + dc));
    }
    this.blocks.delete(key);
    return true;
  }

  // Moves several blocks at once (identified by their current top-left
  // [row, col]) by a fixed (dRow, dCol) offset, as an all-or-nothing
  // operation: if any block's destination would overlap something outside
  // the moving set, nothing moves and this returns false.
  moveBlocks(anchors, dRow, dCol) {
    const moving = anchors.map(([r, c]) => this.getBlockAt(r, c)).filter(Boolean);
    const movingKeys = new Set(moving.map((b) => Grid.key(b.row, b.col)));
    for (const block of moving) {
      if (!this.canPlaceFootprint(block.row + dRow, block.col + dCol, block.words, block.rowSpan, movingKeys)) {
        return false;
      }
    }
    for (const block of moving) {
      for (let dr = 0; dr < block.rowSpan; dr++) {
        for (let dc = 0; dc < block.words; dc++) this.occupied.delete(Grid.key(block.row + dr, block.col + dc));
      }
      this.blocks.delete(Grid.key(block.row, block.col));
    }
    for (const block of moving) {
      block.row += dRow;
      block.col += dCol;
      this.#insert(block.row, block.col, block.words, block.rowSpan, block);
    }
    return true;
  }

  // Places a whole set of blocks at once (row/col given relative to the
  // set's own [0, 0]), offset by (anchorRow, anchorCol) -- used for
  // copy/paste and for inserting a decoded library primitive. All-or-
  // nothing: if any block's target cell is already occupied, nothing is
  // placed and this throws.
  placeBatch(relativeBlocks, anchorRow, anchorCol) {
    for (const rb of relativeBlocks) {
      const { words, rowSpan } = rb.raw ? { words: rb.words, rowSpan: rb.rowSpan } : this.footprint(rb.type, rb.params);
      if (!this.canPlaceFootprint(anchorRow + rb.row, anchorCol + rb.col, words, rowSpan)) {
        throw new Error(`Target area is already occupied at [${anchorRow + rb.row}, ${anchorCol + rb.col}].`);
      }
    }
    // A copy/paste (or inserting a decoded library primitive) is a
    // genuinely new instance, not a continuation of the source's own
    // identity -- never carry its `id` over verbatim (that would place
    // two blocks with the same id the moment anything gets pasted), so
    // strip it here and let placeBlock's own fallback generate a fresh
    // one from the pasted-to position instead.
    return relativeBlocks.map((rb) =>
      rb.raw
        ? this.placeRawBlock(anchorRow + rb.row, anchorCol + rb.col, {
            label: rb.type,
            lines: rb.lines,
            words: rb.words,
            rowSpan: rb.rowSpan,
          })
        : this.placeBlock(anchorRow + rb.row, anchorCol + rb.col, rb.type, { ...rb.params, id: '' })
    );
  }

  // Exchanges two blocks' positions -- each moves to the other's former
  // top-left anchor. Tolerates different footprints (a wide block swapping
  // with a single-word one just relocates each independently to the other's
  // anchor); all-or-nothing, same ignore-each-other collision-check shape as
  // moveBlocks (a block's own former footprint never blocks its swap partner).
  swapBlocks(anchorA, anchorB) {
    const [ra, ca] = anchorA;
    const [rb, cb] = anchorB;
    const a = this.getBlockAt(ra, ca);
    const b = this.getBlockAt(rb, cb);
    if (!a || !b || a === b) return false;
    const ignoreKeys = new Set([Grid.key(a.row, a.col), Grid.key(b.row, b.col)]);
    if (!this.canPlaceFootprint(b.row, b.col, a.words, a.rowSpan, ignoreKeys)) return false;
    if (!this.canPlaceFootprint(a.row, a.col, b.words, b.rowSpan, ignoreKeys)) return false;
    // The two checks above each ignore BOTH old footprints, so they can't
    // see the two NEW footprints colliding with each other (e.g. a narrow
    // block swapping into the middle of where a wide one lands) -- placing
    // both anyway would silently overwrite `occupied` entries and corrupt
    // the grid. Reject the swap outright when the new rectangles intersect.
    const newRowsOverlap = b.row < a.row + b.rowSpan && a.row < b.row + a.rowSpan;
    const newColsOverlap = b.col < a.col + b.words && a.col < b.col + a.words;
    if (newRowsOverlap && newColsOverlap) return false;

    for (const blk of [a, b]) {
      for (let dr = 0; dr < blk.rowSpan; dr++) {
        for (let dc = 0; dc < blk.words; dc++) this.occupied.delete(Grid.key(blk.row + dr, blk.col + dc));
      }
      this.blocks.delete(Grid.key(blk.row, blk.col));
    }
    const [aRow, aCol] = [a.row, a.col];
    a.row = b.row;
    a.col = b.col;
    b.row = aRow;
    b.col = aCol;
    this.#insert(a.row, a.col, a.words, a.rowSpan, a);
    this.#insert(b.row, b.col, b.words, b.rowSpan, b);
    return true;
  }

  // Shifts every block at/after `atRow`/`atCol` by one row/column to make
  // room for a blank one. Always succeeds -- a uniform translation of
  // everything at/after an index can never collide with itself or with
  // anything before the index, so this is just a filtered moveBlocks call
  // with no new collision logic needed.
  insertRow(atRow) {
    const anchors = this.allBlocks()
      .filter((b) => b.row >= atRow)
      .map((b) => [b.row, b.col]);
    return this.moveBlocks(anchors, 1, 0);
  }

  insertColumn(atCol) {
    const anchors = this.allBlocks()
      .filter((b) => b.col >= atCol)
      .map((b) => [b.row, b.col]);
    return this.moveBlocks(anchors, 0, 1);
  }

  // Same as insertRow/insertColumn, but only shifts blocks whose own
  // footprint actually overlaps the given row/column range -- everything
  // else in the grid, even at the same row/col index, is left untouched.
  // Used by app.js's resizeBlockToFitParams: growing one block's width (or
  // height) should only ever displace blocks that could actually collide
  // with its new footprint, i.e. ones sharing at least one of its rows (or
  // columns) -- not every block anywhere in the grid that merely happens to
  // sit at the same column (or row) index in a completely unrelated part
  // of the diagram, the way the plain grid-wide insertRow/insertColumn
  // would.
  insertColumnInRows(atCol, rowStart, rowEnd) {
    const anchors = this.allBlocks()
      .filter((b) => b.col >= atCol && b.row < rowEnd && b.row + b.rowSpan > rowStart)
      .map((b) => [b.row, b.col]);
    return this.moveBlocks(anchors, 0, 1);
  }

  insertRowInColumns(atRow, colStart, colEnd) {
    const anchors = this.allBlocks()
      .filter((b) => b.row >= atRow && b.col < colEnd && b.col + b.words > colStart)
      .map((b) => [b.row, b.col]);
    return this.moveBlocks(anchors, 1, 0);
  }

  // Inverse of insertRow/insertColumn: deletes whatever's entirely inside
  // the target row/column, then shifts everything after it back by one to
  // close the gap. Refuses (returns false, nothing changed) if any block
  // only *partially* overlaps the target index -- a block spanning multiple
  // rows/columns can't have one row/column shaved out of the middle of its
  // shape, so that has to be resolved by the caller first (move or delete
  // the block) rather than silently corrupting it. A block entirely
  // contained in the target row/column (the common case) is deleted
  // outright as part of the removal, same as a spreadsheet's "delete row."
  removeRow(atRow) {
    for (const block of this.allBlocks()) {
      const spansRow = block.row <= atRow && atRow < block.row + block.rowSpan;
      if (spansRow && !(block.row === atRow && block.rowSpan === 1)) return false;
    }
    for (const block of this.allBlocks().filter((b) => b.row === atRow)) this.removeBlock(block.row, block.col);
    const anchors = this.allBlocks()
      .filter((b) => b.row > atRow)
      .map((b) => [b.row, b.col]);
    this.moveBlocks(anchors, -1, 0); // a uniform shift-up can never collide, same as insertRow
    return true;
  }

  removeColumn(atCol) {
    for (const block of this.allBlocks()) {
      const spansCol = block.col <= atCol && atCol < block.col + block.words;
      if (spansCol && !(block.col === atCol && block.words === 1)) return false;
    }
    for (const block of this.allBlocks().filter((b) => b.col === atCol)) this.removeBlock(block.row, block.col);
    const anchors = this.allBlocks()
      .filter((b) => b.col > atCol)
      .map((b) => [b.row, b.col]);
    this.moveBlocks(anchors, 0, -1);
    return true;
  }

  // Changes a block's own footprint in place (its anchor stays put) -- for
  // a param edit that changes how many words/rows the block needs (e.g.
  // multiblockpermutation's `words`/`permutation`, or an IO block's
  // `words`). All-or-nothing: frees the old footprint first so growing
  // never collides with itself, then checks the new one fits; on failure
  // the old footprint is restored and this returns false untouched. Callers
  // that want a *guaranteed* fit for a growing block should insertRow/
  // insertColumn to make room first (see app.js's resizeBlockToFitParams).
  resizeBlock(row, col, newWords, newRowSpan) {
    const block = this.getBlockAt(row, col);
    if (!block) return false;
    if (block.words === newWords && block.rowSpan === newRowSpan) return true;

    const blockKey = Grid.key(block.row, block.col);
    const restore = () => {
      for (let dr = 0; dr < block.rowSpan; dr++) {
        for (let dc = 0; dc < block.words; dc++) this.occupied.set(Grid.key(block.row + dr, block.col + dc), blockKey);
      }
    };
    for (let dr = 0; dr < block.rowSpan; dr++) {
      for (let dc = 0; dc < block.words; dc++) this.occupied.delete(Grid.key(block.row + dr, block.col + dc));
    }
    if (!this.canPlaceFootprint(block.row, block.col, newWords, newRowSpan)) {
      restore();
      return false;
    }
    block.words = newWords;
    block.rowSpan = newRowSpan;
    for (let dr = 0; dr < newRowSpan; dr++) {
      for (let dc = 0; dc < newWords; dc++) this.occupied.set(Grid.key(block.row + dr, block.col + dc), blockKey);
    }
    return true;
  }

  // Returns the block occupying [row, col] (even if it isn't the block's own
  // top-left cell), or null.
  getBlockAt(row, col) {
    const key = this.occupied.get(Grid.key(row, col));
    return key ? this.blocks.get(key) : null;
  }

  allBlocks() {
    return [...this.blocks.values()];
  }

  // True if some *other* block already carries `id` -- `exclude` is the
  // block being edited (a block always "conflicts" with its own current
  // id otherwise, since it hasn't changed yet at the point this is
  // typically called from). Used by the editor's id field to validate an
  // edit before committing it (see app.js) -- raw (non-decomposed,
  // id-less) blocks never participate, so pasting a raw library chunk
  // can't trip this check.
  isIdTaken(id, exclude) {
    for (const block of this.blocks.values()) {
      if (block === exclude || block.raw) continue;
      if (block.params.id === id) return true;
    }
    return false;
  }

  clear() {
    this.blocks.clear();
    this.occupied.clear();
  }

  // Lets a caller try a speculative sequence of mutations (e.g.
  // pseudocodeLayout.js's alignDeclaredOutputs) and cleanly undo them all
  // if the result turns out invalid, without needing its own bespoke
  // undo bookkeeping. `occupied`'s values are plain "row,col" key strings
  // (safe to share), but block objects are mutated in place elsewhere
  // (insertRow/insertColumn/swapBlocks reassign a block's own .row/.col) --
  // so each block needs a real copy, not just a re-referenced Map entry.
  snapshot() {
    return {
      blocks: new Map([...this.blocks].map(([key, block]) => [key, { ...block, params: { ...block.params } }])),
      occupied: new Map(this.occupied),
    };
  }

  restore(snapshot) {
    this.blocks = snapshot.blocks;
    this.occupied = snapshot.occupied;
  }

  isEmpty() {
    return this.blocks.size === 0;
  }

  dimensions() {
    let maxRow = -1;
    let maxCol = -1;
    for (const block of this.blocks.values()) {
      maxRow = Math.max(maxRow, block.row + block.rowSpan - 1);
      maxCol = Math.max(maxCol, block.col + block.words - 1);
    }
    return { rows: maxRow + 1, cols: maxCol + 1 };
  }
}
