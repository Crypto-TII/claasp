// Readable bus-oriented synthesis for scalar expression DAGs.
//
// Unlike the conservative fallback, this keeps unary calls on their input
// lane and draws a binary call in one row: one argument stays vertical while
// the other arrives from the side. Temporary assignment names are aliases,
// not mandatory intermediate_output boxes. A final cycle-safe rewiring pass
// restores output[i] beneath its corresponding state input lane without a
// swap or multiblock-permutation component.
import { BLOCK_TYPES, blockRowSpan, blockWords, defaultParams, setComponentSidePort } from '../../blockCatalog.js';
import { checkConnectivity } from '../../connectivity.js';
import { Grid } from '../../grid.js';

// Keep this in lockstep with structural equivalence: Boolean gates are
// treated as unordered there, while arithmetic calls retain their parsed
// argument order even when the underlying operation is mathematically
// commutative.  Routing must not silently broaden the graph semantics.
// Boolean routes may choose physical ports freely; semantic-auto binds
// logical operand order visibly before accepting the result. Arithmetic
// and other noncommutative operations retain geometric ordered routing.
const COMMUTATIVE = new Set(['xor', 'and', 'or', 'typedbox']);

function naturalNameOrder(a, b) {
  return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
}

function callParams(node, side = 'left') {
  const params = { ...defaultParams(node.typeName), ...node.params };
  if (['xor', 'and', 'or'].includes(node.typeName)) params.inputs = node.args.length;
  if (node.args.length === 2) {
    if (BLOCK_TYPES[node.typeName]?.params.some((param) => param.name === 'side')) params.side = side;
    else {
      setComponentSidePort(params, side, 'in');
      setComponentSidePort(params, side === 'left' ? 'right' : 'left', 'off');
    }
  }
  return params;
}

export function graphToGridDirectBus(targetOrder, { diagnostics } = {}) {
  const outputTargets = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  if (outputTargets.length === 0) throw new Error('direct bus layout: no outputs');

  // Intern tuple projections by owner/index. Named references are aliases,
  // and independent references to one wide result must share its live lane.
  const projections = new Map();
  const scanned = new Set();
  const bare = (raw) => {
    while (raw?.kind === 'named') raw = raw.inner;
    return raw;
  };
  function scan(raw) {
    const node = bare(raw);
    if (!node || scanned.has(node)) return;
    scanned.add(node);
    if (node.kind === 'index') {
      const owner = bare(node.of);
      if (owner?.kind === 'call') {
        if (!projections.has(owner)) projections.set(owner, new Map());
        projections.get(owner).set(node.index, { kind: 'tuple-index', of: owner, index: node.index });
      }
      scan(owner);
    } else if (node.kind === 'call') node.args.forEach(scan);
  }
  outputTargets.forEach((target) => scan(target.node));
  const tupleCalls = new Set([...projections]
    .filter(([, indices]) => Math.max(...indices.keys()) > 1).map(([call]) => call));
  for (const call of tupleCalls) {
    const indices = [...projections.get(call).keys()].sort((a, b) => a - b);
    if (BLOCK_TYPES[call.typeName]?.inputs !== 1 || indices.length !== call.args.length
        || indices.some((index, position) => index !== position + 1)) {
      throw new Error('direct bus layout: partial or changing-width tuples require the conservative fallback');
    }
  }

  function canonical(node) {
    while (node.kind === 'named') node = node.inner;
    if (node.kind === 'index') {
      const owner = bare(node.of);
      if (tupleCalls.has(owner)) return projections.get(owner).get(node.index);
      if (node.index !== 1) throw new Error('direct bus layout: tuple results require the conservative fallback');
      return canonical(node.of);
    }
    return node;
  }

  // Unlike canonical(), this shape deliberately treats a reference to a
  // named assignment as an opaque value. That preserves the phase boundary
  // expressed by pseudocode such as `d = xor(c1, rotate(c2))` instead of
  // expanding the complete definitions of c1/c2 into d's local shape.
  function assignmentShape(raw, top = true) {
    let node = raw;
    if (top && node?.kind === 'named') node = node.inner;
    if (!node) return '?';
    if (node.kind === 'named' || node.kind === 'input') return 'v';
    if (node.kind === 'index') return `index(${node.index},${assignmentShape(node.of, false)})`;
    if (node.kind !== 'call') return node.kind;
    let args = node.args.map((arg) => assignmentShape(arg, false));
    if (COMMUTATIVE.has(node.typeName)) args = args.sort();
    // Parameter values intentionally do not participate: rotate-by-2 and
    // rotate-by-17 are parallel members of the same operation family.
    return `${node.typeName}/${node.args.length}(${args.join(',')})`;
  }

  function assignmentRoot(target) {
    return target.node?.kind === 'named' ? target.node.inner : target.node;
  }

  function directCallChildren(root) {
    if (root?.kind !== 'call') return [];
    return root.args.filter((arg) => arg?.kind === 'call');
  }

  // A family of outputs may be written as independent associative
  // reductions whose side terms are themselves short pipelines, e.g.
  //   xor(xor(a, b), shift(and(c, d)))
  // repeated for several lanes. A depth-first walk finishes the first
  // reduction before even starting the next side pipeline, visually hiding
  // the repeated AND->SHIFT / OR->SHIFT motif. Detect the algebraic shape,
  // independent of operator names and constants, so all side pipelines are
  // completed as one phase before any final reductions are drawn.
  function siblingReductionFamily(start, targets) {
    const members = [];
    for (let index = start; index < targets.length && targets[index].isOutput; index++) {
      const root = assignmentRoot(targets[index]);
      if (root?.kind !== 'call' || !COMMUTATIVE.has(root.typeName) || root.args.length !== 2) break;
      const terms = [];
      const flatten = (raw, top = false) => {
        if (!top && raw?.kind === 'named') {
          terms.push(canonical(raw));
          return;
        }
        const node = canonical(raw);
        if (node?.kind === 'call' && node.typeName === root.typeName && node.args.length === 2) {
          node.args.forEach((arg) => flatten(arg));
        } else {
          terms.push(node);
        }
      };
      flatten(root, true);
      members.push({ root, terms });
    }
    if (members.length < 3) return null;
    const typeName = members[0].root.typeName;
    const termCount = members[0].terms.length;
    if (termCount < 3 || members.some((member) => member.root.typeName !== typeName
      || member.terms.length !== termCount)) return null;
    const branchCalls = members.flatMap((member, memberIndex) => member.terms
      .filter((term) => term?.kind === 'call' && term.typeName !== typeName)
      .map((term, termIndex) => ({ term, memberIndex, termIndex })));
    if (branchCalls.length < members.length) return null;
    const heightMemo = new Map();
    const height = (node) => {
      node = canonical(node);
      if (!node || node.kind !== 'call') return 0;
      if (heightMemo.has(node)) return heightMemo.get(node);
      const value = 1 + Math.max(0, ...node.args.map(height));
      heightMemo.set(node, value);
      return value;
    };
    branchCalls.sort((a, b) => height(b.term) - height(a.term)
      || a.memberIndex - b.memberIndex || a.termIndex - b.termIndex);
    return { members, branchCalls };
  }

  function sideMergeRecord(core) {
    if (core?.kind !== 'call' || core.args.length !== 2) return null;
    const carriedIndex = core.args.findIndex((arg) => arg?.kind === 'named' || arg?.kind === 'input');
    if (carriedIndex < 0) return null;
    const side = core.args[1 - carriedIndex];
    if (side?.kind !== 'call' || side.args.length !== 2) return null;
    const unaryIndex = side.args.findIndex((arg) => arg?.kind === 'call' && arg.args.length === 1);
    if (unaryIndex < 0) return null;
    const unary = side.args[unaryIndex];
    const negatedRaw = unary.args[0];
    const otherRaw = side.args[1 - unaryIndex];
    const isReference = (arg) => arg?.kind === 'named' || arg?.kind === 'input';
    if (!isReference(negatedRaw) || !isReference(otherRaw)) return null;
    return {
      root: core,
      carried: canonical(core.args[carriedIndex]),
      side,
      unary,
      negated: canonical(negatedRaw),
      other: canonical(otherRaw),
    };
  }

  function independentSideMergeGroups(members) {
    const records = members.map(({ core }) => sideMergeRecord(core));
    if (records.some((record) => !record)) return null;
    const parent = records.map((_, index) => index);
    const find = (index) => parent[index] === index ? index : (parent[index] = find(parent[index]));
    const join = (a, b) => { a = find(a); b = find(b); if (a !== b) parent[b] = a; };
    const owner = new Map();
    records.forEach((record, index) => {
      for (const value of [record.carried, record.negated, record.other]) {
        if (owner.has(value)) join(index, owner.get(value));
        else owner.set(value, index);
      }
    });
    const grouped = new Map();
    records.forEach((record, index) => {
      const root = find(index);
      if (!grouped.has(root)) grouped.set(root, []);
      grouped.get(root).push(record);
    });
    const groups = [...grouped.values()];
    if (groups.length < 2 || groups.some((group) => group.length < 3)) return null;
    const size = groups[0].length;
    if (groups.some((group) => group.length !== size
      || new Set(group.flatMap((record) => [record.carried, record.negated, record.other])).size !== size)) return null;
    return groups;
  }

  const seen = new Set();
  const inputs = [];
  const operations = [];
  const alignmentBeforeOperation = new Map();
  const groupedSideMergeBeforeOperation = new Map();
  function visit(raw) {
    const node = canonical(raw);
    if (seen.has(node)) return;
    seen.add(node);
    if (node.kind === 'input') {
      if (node.wordGroup) throw new Error('direct bus layout: grouped inputs require the conservative fallback');
      inputs.push(node);
      return;
    }
    if (node.kind === 'tuple-index') { visit(node.of); return; }
    if (node.kind !== 'call') throw new Error(`direct bus layout: unsupported node ${node.kind}`);
    if (!tupleCalls.has(node) && node.args.length > 3) throw new Error('direct bus layout: components with more than three arguments require the conservative fallback');
    const params = callParams(node);
    if (!tupleCalls.has(node) && blockWords(node.typeName, params) !== 1) throw new Error('direct bus layout: wide components require the conservative fallback');
    node.args.forEach(visit);
    operations.push(node);
  }
  // Preserve explicit assignment order when it is available. A named
  // intermediate is an author-provided phase boundary: finishing later
  // consumers merely because one branch is ready destroys parallel layers
  // (for example, it interleaves a rotate with an unfinished family of
  // parity reductions). Only retain assignments that actually contribute
  // to an output, so dead pseudocode does not become visible circuitry.
  const outputReachable = new Set();
  function markReachable(raw) {
    const node = canonical(raw);
    if (outputReachable.has(node)) return;
    outputReachable.add(node);
    if (node.kind === 'call') node.args.forEach(markReachable);
    else if (node.kind === 'tuple-index') markReachable(node.of);
  }
  outputTargets.forEach((target) => markReachable(target.node));
  const PHASE_SAFE_TYPES = new Set(['xor', 'and', 'or', 'not', 'rotate', 'shift', 'constant']);
  const preserveAssignmentPhases = [...outputReachable].every((node) =>
    node.kind !== 'call' || PHASE_SAFE_TYPES.has(node.typeName));
  const orderedTargets = targetOrder.filter((target) => outputReachable.has(canonical(target.node)));
  for (let start = 0; preserveAssignmentPhases && start < orderedTargets.length;) {
    const reductions = siblingReductionFamily(start, orderedTargets);
    if (reductions) {
      reductions.branchCalls.forEach(({ term }) => visit(term));
      // Visit the penultimate reductions across all siblings before their
      // roots. This retains a visible reduction layer even for the usual
      // left-associated source-code spelling.
      reductions.members.forEach(({ root }) => {
        root.args.filter((arg) => canonical(arg)?.kind === 'call'
          && canonical(arg).typeName === root.typeName).forEach(visit);
      });
      reductions.members.forEach(({ root }) => visit(root));
      start += reductions.members.length;
      continue;
    }
    const firstRoot = assignmentRoot(orderedTargets[start]);
    const candidates = [assignmentShape(firstRoot), ...directCallChildren(firstRoot).map((child) => assignmentShape(child))];
    let best = null;
    for (const shape of new Set(candidates)) {
      const members = [];
      let roots = 0;
      let wrappers = 0;
      for (let index = start; index < orderedTargets.length; index++) {
        const root = assignmentRoot(orderedTargets[index]);
        if (assignmentShape(root) === shape) {
          members.push({ root, core: root, wrapped: false });
          roots++;
          continue;
        }
        const core = directCallChildren(root).find((child) => assignmentShape(child) === shape);
        if (!core) break;
        members.push({ root, core, wrapped: true });
        wrappers++;
      }
      if (roots > 0 && wrappers > 0 && (!best || members.length > best.members.length)) {
        best = { members };
      }
    }
    if (best && best.members.length > 1) {
      // Complete the repeated cores as a visual layer, then advance to the
      // exceptional/unary wrappers. This recovers boundaries even when the
      // pseudocode fused two consecutive transformations into one RHS.
      const carried = best.members.map(({ core }) => {
        if (core?.kind !== 'call') return null;
        const directValues = core.args.filter((arg) => arg?.kind === 'named');
        return directValues.length === 1 ? canonical(directValues[0]) : null;
      });
      if (carried.every(Boolean) && new Set(carried).size === carried.length) {
        // The next repeated family exposes one directly-carried value per
        // result. Its target order is therefore a consumer-derived frontier
        // order. If the preceding phase produced those values in another
        // order, materialize the difference as an explicit permutation.
        alignmentBeforeOperation.set(operations.length, carried);
      }
      const sideMergeGroups = independentSideMergeGroups(best.members);
      if (sideMergeGroups) groupedSideMergeBeforeOperation.set(operations.length, sideMergeGroups);
      best.members.forEach(({ core }) => visit(core));
      best.members.filter(({ wrapped }) => wrapped).forEach(({ root }) => visit(root));
      start += best.members.length;
    } else {
      visit(orderedTargets[start].node);
      start++;
    }
  }
  if (!preserveAssignmentPhases) outputTargets.forEach((target) => visit(target.node));
  inputs.sort(naturalNameOrder);

  // Dependency depth identifies independent calls that may share a row.
  // Scalar programs keep their existing topological discovery order.
  // Wide-result programs group equal-depth tuple frontiers below; the bus
  // router then prepares all their input lanes before drawing the layer.
  const depthMemo = new Map();
  function operationDepth(raw) {
    const node = canonical(raw);
    if (node.kind === 'input') return 0;
    if (node.kind === 'tuple-index') return operationDepth(node.of);
    if (depthMemo.has(node)) return depthMemo.get(node);
    const depth = 1 + Math.max(0, ...node.args.map(operationDepth));
    depthMemo.set(node, depth);
    return depth;
  }

  // Wide-result programs need whole frontiers ready before their tuple
  // layer is drawn. Output-by-output DFS otherwise interleaves a later
  // scalar round with the other tuples in an earlier parallel layer.
  if (tupleCalls.size && !preserveAssignmentPhases) {
    operations.sort((a, b) => operationDepth(a) - operationDepth(b)
      || Number(tupleCalls.has(a)) - Number(tupleCalls.has(b))
      || (tupleCalls.has(a) && tupleCalls.has(b) ? a.typeName.localeCompare(b.typeName) : 0));
  }

  const roots = outputTargets.map((target) => canonical(target.node));
  if (new Set(roots).size !== roots.length) {
    throw new Error('direct bus layout: duplicate output values require the conservative fallback');
  }

  const uses = new Map();
  const addUse = (node) => uses.set(node, (uses.get(node) || 0) + 1);
  for (const node of operations) node.args.map(canonical).forEach(addUse);
  roots.forEach(addUse);

  const grid = new Grid();
  const live = new Set();
  const colOf = new Map();
  const valueAt = new Map();
  let row = 0;

  // Infer the state lane a value conceptually continues, using only graph
  // shape. Unary calls preserve their operand's lane. At a merge, a unique
  // direct public operand is the carried state value; otherwise the first
  // recursively identifiable operand supplies the lane. This is the same
  // generic signal used by hand-drawn Feistel/ARX circuits: for
  // xor(F(input[1]), input[2]), the result continues input[2]'s lane.
  const preferredInputMemo = new Map();
  function preferredInput(raw) {
    const node = canonical(raw);
    if (preferredInputMemo.has(node)) return preferredInputMemo.get(node);
    let preferred = null;
    if (node.kind === 'input') {
      preferred = node;
    } else if (node.kind === 'tuple-index') {
      preferred = preferredInput(node.of.args[node.index - 1]);
    } else if (node.kind === 'call' && node.args.length === 1) {
      preferred = preferredInput(node.args[0]);
    } else if (node.kind === 'call') {
      const directPublic = node.args
        .map(canonical)
        .filter((arg) => arg.kind === 'input' && !(arg.secret || arg.groupSecret));
      if (directPublic.length === 1) preferred = directPublic[0];
      else {
        const candidates = node.args.map(preferredInput).filter(Boolean);
        preferred = candidates[0] || null;
      }
    }
    preferredInputMemo.set(node, preferred);
    return preferred;
  }

  for (let col = 0; col < inputs.length; col++) {
    const node = inputs[col];
    grid.placeBlock(row, col, 'input', {
      ...defaultParams('input'),
      secrecy: node.secret || node.groupSecret ? 'secret' : 'public',
    });
    live.add(col);
    colOf.set(node, col);
    valueAt.set(col, node);
  }
  row++;

  function fillVerticals(excluded = new Set()) {
    for (const col of live) {
      if (!excluded.has(col) && !grid.getBlockAt(row, col)) {
        grid.placeBlock(row, col, 'wire', { ...defaultParams('wire'), direction: 'top_to_bottom' });
      }
    }
  }

  function nearestFree(source) {
    const max = live.size ? Math.max(...live) : -1;
    for (let distance = 1; distance <= max + 2; distance++) {
      const left = source - distance;
      if (left >= 0 && !live.has(left)) return left;
      const right = source + distance;
      if (!live.has(right)) return right;
    }
    return max + 1;
  }

  function horizontalRoute(source, target, keepSource) {
    const rightward = source < target;
    const sourceDirection = rightward ? 'top_to_right' : 'top_to_left';
    const splitDirection = rightward ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom';
    grid.placeBlock(row, source, keepSource ? 'split' : 'wire', keepSource
      ? { ...defaultParams('split'), direction: splitDirection }
      : { ...defaultParams('wire'), direction: sourceDirection });
    const step = rightward ? 1 : -1;
    for (let col = source + step; col !== target; col += step) {
      if (live.has(col)) {
        grid.placeBlock(row, col, 'double_wire', {
          ...defaultParams('double_wire'),
          variant: rightward ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left',
        });
      } else {
        grid.placeBlock(row, col, 'wire', {
          ...defaultParams('wire'),
          direction: rightward ? 'left_to_right' : 'right_to_left',
        });
      }
    }
    grid.placeBlock(row, target, 'wire', {
      ...defaultParams('wire'),
      direction: rightward ? 'left_to_bottom' : 'right_to_bottom',
    });
    fillVerticals(new Set([source, target]));
  }

  // Consumes one graph use and materializes that use in an otherwise-empty
  // lane. The original stays vertical only if later consumers still need it.
  function branchUse(node, requestedTarget = null) {
    const source = colOf.get(node);
    const target = requestedTarget ?? nearestFree(source);
    if (live.has(target)) throw new Error('direct bus layout: requested branch lane is occupied');
    const remaining = (uses.get(node) || 0) - 1;
    uses.set(node, remaining);
    horizontalRoute(source, target, remaining > 0);
    if (remaining === 0) {
      live.delete(source);
      valueAt.delete(source);
    }
    live.add(target);
    valueAt.set(target, node);
    if (remaining === 0) colOf.set(node, target);
    row++;
    return target;
  }

  // Consume the current vertical occurrence while moving the value that
  // later consumers still need into a temporary lane. This is the mirror
  // image of branchUse(): it keeps a carried/state result on its main trunk
  // instead of moving the current merge off to the side.
  function preserveFutureUses(node) {
    const source = colOf.get(node);
    const target = nearestFree(source);
    const remaining = (uses.get(node) || 0) - 1;
    if (remaining <= 0) return source;
    uses.set(node, remaining);
    horizontalRoute(source, target, true);
    live.add(target);
    valueAt.set(target, node);
    colOf.set(node, target);
    row++;
    return source;
  }

  function consumeLateral(node, componentCol) {
    const source = colOf.get(node);
    const rightward = source < componentCol;
    const remaining = (uses.get(node) || 0) - 1;
    uses.set(node, remaining);
    const keep = remaining > 0;
    grid.placeBlock(row, source, keep ? 'split' : 'wire', keep
      ? { ...defaultParams('split'), direction: rightward ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom' }
      : { ...defaultParams('wire'), direction: rightward ? 'top_to_right' : 'top_to_left' });
    const step = rightward ? 1 : -1;
    for (let col = source + step; col !== componentCol; col += step) {
      if (live.has(col)) {
        grid.placeBlock(row, col, 'double_wire', {
          ...defaultParams('double_wire'),
          variant: rightward ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left',
        });
      } else {
        grid.placeBlock(row, col, 'wire', {
          ...defaultParams('wire'),
          direction: rightward ? 'left_to_right' : 'right_to_left',
        });
      }
    }
    if (!keep) {
      live.delete(source);
      valueAt.delete(source);
    }
    return rightward ? 'left' : 'right';
  }

  function alignLiveFrontier(preferred) {
    if (preferred.some((node) => !live.has(colOf.get(node)))) return;
    const preferredSet = new Set(preferred);
    const extraEntries = [...live].sort((a, b) => a - b)
      .map((col) => ({ col, node: valueAt.get(col) }))
      .filter(({ node }) => !preferredSet.has(node));
    const extras = extraEntries.map(({ node }) => node);
    const desiredValues = [...extras, ...preferred];
    if (desiredValues.length !== live.size || new Set(desiredValues).size !== live.size) return;
    const prefixExtras = extraEntries.every(({ col }, index) => col === index);
    const permutedValues = prefixExtras ? preferred : desiredValues;
    const sourceColumns = permutedValues.map((node) => colOf.get(node)).sort((a, b) => a - b);
    const sourceValues = sourceColumns.map((col) => valueAt.get(col));
    const targetStart = prefixExtras ? extras.length : 0;
    const targetColumns = permutedValues.map((_, index) => targetStart + index);
    const permutation = sourceValues.map((node) => desiredValues.indexOf(node));
    if (prefixExtras) {
      for (let index = 0; index < permutation.length; index++) permutation[index] -= extras.length;
    }
    if (sourceColumns.every((col, index) => col === targetColumns[index])
        && permutation.every((destination, source) => destination === source)) return;
    const anchor = targetStart;
    const words = Math.max(sourceColumns.at(-1), targetColumns.at(-1)) - anchor + 1;
    const params = {
      ...defaultParams('multiblockpermutation'),
      permutation: permutation.join(','),
      words: String(words),
      activeInputs: sourceColumns.map((col) => col - anchor).join(','),
      activeOutputs: targetColumns.map((col) => col - anchor).join(','),
      borders: 'invisible',
    };
    grid.placeBlock(row, anchor, 'multiblockpermutation', params);
    const span = blockRowSpan('multiblockpermutation', params);
    if (prefixExtras) {
      for (let offset = 0; offset < span; offset++) {
        for (const { col } of extraEntries) {
          grid.placeBlock(row + offset, col, 'wire', { ...defaultParams('wire'), direction: 'top_to_bottom' });
        }
      }
    }
    row += span;
    for (const col of sourceColumns) {
      live.delete(col);
      valueAt.delete(col);
    }
    permutedValues.forEach((node, index) => {
      const col = targetColumns[index];
      live.add(col);
      valueAt.set(col, node);
      colOf.set(node, col);
    });
  }

  const groupedSideMergeOperations = new Set();

  function renderGroupedSideMerges(groups) {
    for (const group of groups) {
      const workspace = (live.size ? Math.max(...live) + 1 : 0);
      const unaryLanes = group.map((_, index) => workspace + 2 * index);
      const otherLanes = group.map((_, index) => workspace + 2 * index + 1);

      // Prepare independent copies first. Each transfer owns a row, keeping
      // routing collision-free; the actual operation family then shares a
      // single aligned row.
      group.forEach((record, index) => branchUse(record.negated, unaryLanes[index]));
      const unaryLaneSet = new Set(unaryLanes);
      group.forEach((record, index) => {
        const lane = unaryLanes[index];
        grid.placeBlock(row, lane, record.unary.typeName, callParams(record.unary));
        live.delete(lane);
        valueAt.delete(lane);
        colOf.set(record.unary, lane);
        live.add(lane);
        valueAt.set(lane, record.unary);
        groupedSideMergeOperations.add(record.unary);
      });
      fillVerticals(unaryLaneSet);
      row++;

      group.forEach((record, index) => branchUse(record.other, otherLanes[index]));
      const pairLanes = new Set([...unaryLanes, ...otherLanes]);
      group.forEach((record, index) => {
        const unaryLane = unaryLanes[index];
        const otherLane = otherLanes[index];
        grid.placeBlock(row, unaryLane, record.side.typeName, callParams(record.side, 'right'));
        grid.placeBlock(row, otherLane, 'wire', { ...defaultParams('wire'), direction: 'top_to_left' });
        live.delete(unaryLane);
        live.delete(otherLane);
        valueAt.delete(unaryLane);
        valueAt.delete(otherLane);
        uses.set(record.unary, Math.max(0, (uses.get(record.unary) || 0) - 1));
        colOf.set(record.side, unaryLane);
        if ((uses.get(record.side) || 0) > 0) {
          live.add(unaryLane);
          valueAt.set(unaryLane, record.side);
        }
        groupedSideMergeOperations.add(record.side);
      });
      fillVerticals(pairLanes);
      row++;

      // Return every result to its carried lane. At this point all cyclic
      // side uses in the group have been consumed, so the carried occurrence
      // is normally its last use and remains on the main frontier.
      for (const record of group) {
        const componentCol = colOf.get(record.carried);
        const side = consumeLateral(record.side, componentCol);
        uses.set(record.carried, Math.max(0, (uses.get(record.carried) || 0) - 1));
        grid.placeBlock(row, componentCol, record.root.typeName, callParams(record.root, side));
        const sideCol = colOf.get(record.side);
        const lo = Math.min(sideCol, componentCol);
        const hi = Math.max(sideCol, componentCol);
        fillVerticals(new Set(Array.from({ length: hi - lo + 1 }, (_, index) => lo + index)));
        live.delete(componentCol);
        valueAt.delete(componentCol);
        colOf.set(record.root, componentCol);
        if ((uses.get(record.root) || 0) > 0) {
          live.add(componentCol);
          valueAt.set(componentCol, record.root);
        }
        groupedSideMergeOperations.add(record.root);
        row++;
      }
    }
  }

  for (let operationIndex = 0; operationIndex < operations.length; operationIndex++) {
    const preferredFrontier = alignmentBeforeOperation.get(operationIndex);
    if (preferredFrontier) alignLiveFrontier(preferredFrontier);
    const groupedSideMerges = groupedSideMergeBeforeOperation.get(operationIndex);
    if (groupedSideMerges) renderGroupedSideMerges(groupedSideMerges);
    const node = operations[operationIndex];
    if (groupedSideMergeOperations.has(node)) continue;
    const args = node.args.map(canonical);

    if (tupleCalls.has(node)) {
      const batch = [];
      for (let index = operationIndex; index < operations.length; index++) {
        const candidate = operations[index];
        if (!tupleCalls.has(candidate) || candidate.typeName !== node.typeName
            || operationDepth(candidate) !== operationDepth(node)) break;
        const values = candidate.args.map(canonical);
        const columns = values.map((arg) => colOf.get(arg));
        const inPlace = new Set(values).size === values.length
          && values.every((arg, i) => uses.get(arg) === 1 && columns[i] === columns[0] + i);
        const base = inPlace ? columns[0] : Math.max(-1, ...live) + 1;
        const lanes = inPlace ? columns : values.map((arg, i) => branchUse(arg, base + i));
        if (inPlace) values.forEach((arg) => uses.set(arg, 0));
        batch.push({ candidate, base, lanes });
      }
      const occupied = new Set(batch.flatMap(({ lanes }) => lanes));
      for (const { candidate, base, lanes } of batch) {
        grid.placeBlock(row, base, candidate.typeName, { ...callParams(candidate), words: lanes.length });
      }
      fillVerticals(occupied);
      for (const lane of occupied) { live.delete(lane); valueAt.delete(lane); }
      for (const { candidate, base } of batch) {
        for (const [index, projection] of projections.get(candidate)) {
          const col = base + index - 1;
          colOf.set(projection, col);
          if ((uses.get(projection) || 0) > 0) {
            live.add(col); valueAt.set(col, projection);
          }
        }
      }
      row++;
      operationIndex += batch.length - 1;
      continue;
    }

    // Consecutive unary calls at the same dependency depth can occupy one
    // row when each consumes its operand's last use. Their lanes are then
    // disjoint by construction, requiring no routing or crossings.
    if (args.length === 1 && (uses.get(args[0]) || 0) === 1) {
      const batch = [];
      const occupied = new Set();
      for (let index = operationIndex; index < operations.length; index++) {
        const candidate = operations[index];
        if (operationDepth(candidate) !== operationDepth(node) || candidate.args.length !== 1) break;
        const argument = canonical(candidate.args[0]);
        const col = colOf.get(argument);
        if ((uses.get(argument) || 0) !== 1 || col === undefined || occupied.has(col)) break;
        batch.push({ candidate, argument, col });
        occupied.add(col);
      }
      if (batch.length > 1) {
        for (const item of batch) {
          uses.set(item.argument, 0);
          grid.placeBlock(row, item.col, item.candidate.typeName, callParams(item.candidate));
        }
        fillVerticals(occupied);
        for (const item of batch) {
          live.delete(item.col);
          valueAt.delete(item.col);
          colOf.set(item.candidate, item.col);
          if ((uses.get(item.candidate) || 0) > 0) {
            live.add(item.col);
            valueAt.set(item.col, item.candidate);
          }
        }
        row++;
        operationIndex += batch.length - 1;
        continue;
      }
    }

    if (args.length === 0) {
      const col = live.size ? Math.max(...live) + 1 : 0;
      grid.placeBlock(row, col, node.typeName, callParams(node));
      fillVerticals();
      colOf.set(node, col);
      if ((uses.get(node) || 0) > 0) {
        live.add(col);
        valueAt.set(col, node);
      }
      row++;
      continue;
    }

    if (args.length === 1) {
      const arg = args[0];
      let col;
      if ((uses.get(arg) || 0) === 1) {
        col = colOf.get(arg);
        uses.set(arg, 0);
      } else {
        col = branchUse(arg);
      }
      grid.placeBlock(row, col, node.typeName, callParams(node));
      fillVerticals(new Set([col]));
      live.delete(col);
      valueAt.delete(col);
      colOf.set(node, col);
      if ((uses.get(node) || 0) > 0) {
        live.add(col);
        valueAt.set(col, node);
      }
      row++;
      continue;
    }

    if (args.length === 3) {
      // Preserve the catalog's [left, top, right] argument convention. Move
      // the three uses into fresh adjacent lanes first; each transfer owns a
      // row, so this remains collision-free even when all operands started
      // on the same side or are shared elsewhere in the graph.
      const base = live.size ? Math.max(...live) + 1 : 0;
      const lanes = args.map((arg, index) => branchUse(arg, base + index));
      grid.placeBlock(row, lanes[0], 'wire', { ...defaultParams('wire'), direction: 'top_to_right' });
      grid.placeBlock(row, lanes[1], node.typeName, callParams(node));
      grid.placeBlock(row, lanes[2], 'wire', { ...defaultParams('wire'), direction: 'top_to_left' });
      fillVerticals(new Set(lanes));
      for (const lane of lanes) {
        live.delete(lane);
        valueAt.delete(lane);
      }
      colOf.set(node, lanes[1]);
      if ((uses.get(node) || 0) > 0) {
        live.add(lanes[1]);
        valueAt.set(lanes[1], node);
      }
      row++;
      continue;
    }

    let verticalIndex = 1;
    let keepCarriedTrunk = false;
    const inlineCalls = node.args.map((arg, index) => ({ arg, index }))
      .filter(({ arg }) => arg?.kind === 'call');
    if (preserveAssignmentPhases && inlineCalls.length === 1) {
      const inline = inlineCalls[0];
      const otherIndex = 1 - inline.index;
      const other = node.args[otherIndex];
      if (inline.arg.args.length === 1 || inline.arg.typeName === node.typeName) {
        // Unary-then-merge and associative reduction: keep the freshly
        // computed result vertical into its immediate consumer.
        verticalIndex = inline.index;
      } else if (other?.kind === 'named' || other?.kind === 'input' || other?.kind === 'index') {
        // Compound side expression merged with a carried state value: keep
        // the carried value on its main lane and return the result there.
        verticalIndex = otherIndex;
        keepCarriedTrunk = true;
      }
    } else if (COMMUTATIVE.has(node.typeName)) {
      const last = args.map((arg, index) => ({ index, remaining: uses.get(arg) || 0 }))
        .filter(({ remaining }) => remaining === 1);
      if (last.length) verticalIndex = last[0].index;
    } else {
      // Ordered binary blocks have two faithful orientations in the ASCII
      // vocabulary: [top,right] and [left,top]. Prefer the operand whose
      // value expires here as the vertical/replaced lane when its current
      // geometry already matches one of those orientations. This keeps
      // operations such as modadd(rotate(x), y) on rotate(x)'s own lane
      // instead of needlessly copying it to a scratch column, while the
      // port order still extracts the original argument order exactly.
      const expiring = args.map((arg, index) => ({ index, remaining: uses.get(arg) || 0 }))
        .filter(({ remaining }) => remaining === 1);
      const fitting = expiring.find(({ index }) => {
        const verticalCol = colOf.get(args[index]);
        const lateralCol = colOf.get(args[1 - index]);
        return index === 0 ? verticalCol < lateralCol : lateralCol < verticalCol;
      });
      if (fitting) verticalIndex = fitting.index;
    }
    const lateralIndex = 1 - verticalIndex;
    const verticalArg = args[verticalIndex];
    const lateralArg = args[lateralIndex];
    let componentCol;
    let verticalPrepared = false;
    const needsOrderedLeftPort = !COMMUTATIVE.has(node.typeName)
      && ((verticalIndex === 0 && colOf.get(lateralArg) < colOf.get(verticalArg))
        || (verticalIndex === 1 && colOf.get(lateralArg) > colOf.get(verticalArg)));
    if (needsOrderedLeftPort) {
      componentCol = branchUse(verticalArg, Math.max(...live) + 1);
      verticalPrepared = true;
    } else if (keepCarriedTrunk && (uses.get(verticalArg) || 0) > 1) {
      componentCol = preserveFutureUses(verticalArg);
      verticalPrepared = true;
    } else if ((uses.get(verticalArg) || 0) === 1) {
      componentCol = colOf.get(verticalArg);
    } else {
      componentCol = branchUse(verticalArg);
      verticalPrepared = true;
    }
    const side = consumeLateral(lateralArg, componentCol);
    if (!verticalPrepared) uses.set(verticalArg, (uses.get(verticalArg) || 0) - 1);
    const placedParams=callParams(node,side);
    if(node.typeName==='typedbox') {
      const physical=side==='left'?[lateralIndex,verticalIndex]:[verticalIndex,lateralIndex];
      placedParams.operand_order=physical[0]===0?'':'21';
    }
    grid.placeBlock(row, componentCol, node.typeName, placedParams);
    const lo = Math.min(colOf.get(lateralArg), componentCol);
    const hi = Math.max(colOf.get(lateralArg), componentCol);
    fillVerticals(new Set(Array.from({ length: hi - lo + 1 }, (_, index) => lo + index)));
    live.delete(componentCol);
    valueAt.delete(componentCol);
    colOf.set(node, componentCol);
    if ((uses.get(node) || 0) > 0) {
      live.add(componentCol);
      valueAt.set(componentCol, node);
    }
    row++;
  }

  // All computation is done. Only output roots may still be live.
  const rootSet = new Set(roots);
  if ([...live].some((col) => !rootSet.has(valueAt.get(col)))) {
    throw new Error('direct bus layout: an internal value remained live at the output boundary');
  }

  // Place outputs on the state lanes inferred above. Output labels therefore
  // follow the construction's actual permutation: output[2] is leftmost when
  // it directly continues the leftmost input. If inference is incomplete or
  // two results claim one lane, retain the collision-free ordinal fallback.
  let desiredColumns;
  const inferredColumns = roots.map((root) => {
    const input = preferredInput(root);
    return input ? colOf.get(input) : undefined;
  });
  const hasDirectPassthrough = roots.some((root) => root.kind === 'input');
  if ((outputTargets.length === 1 || hasDirectPassthrough)
      && inferredColumns.every((col) => col !== undefined)
      && new Set(inferredColumns).size === inferredColumns.length) {
    desiredColumns = inferredColumns;
  } else if (outputTargets.length === 1) {
    const publicInputs = inputs
      .map((input, col) => ({ input, col }))
      .filter(({ input }) => !(input.secret || input.groupSecret));
    const natural = colOf.get(roots[0]);
    desiredColumns = [publicInputs.length === 1 ? publicInputs[0].col : natural];
  } else {
    const publicColumns = inputs
      .map((input, col) => ({ input, col }))
      .filter(({ input }) => !(input.secret || input.groupSecret))
      .map(({ col }) => col);
    if (publicColumns.length === outputTargets.length) {
      desiredColumns = publicColumns;
    } else {
      const baseCol = Math.max(0, inputs.length - outputTargets.length);
      desiredColumns = roots.map((_, index) => baseCol + index);
    }
  }
  const desired = new Map(roots.map((node, index) => [node, desiredColumns[index]]));
  const initiallyMisaligned = roots.filter((node) => colOf.get(node) !== desired.get(node)).length;

  function moveValue(node, target) {
    const source = colOf.get(node);
    if (source === target) return;
    if (live.has(target)) throw new Error('direct bus layout: attempted to move into an occupied lane');
    horizontalRoute(source, target, false);
    live.delete(source);
    valueAt.delete(source);
    live.add(target);
    valueAt.set(target, node);
    colOf.set(node, target);
    row++;
  }

  while (roots.some((node) => colOf.get(node) !== desired.get(node))) {
    const direct = roots.find((node) => colOf.get(node) !== desired.get(node) && !live.has(desired.get(node)));
    if (direct) {
      moveValue(direct, desired.get(direct));
      continue;
    }

    // Remaining mismatch is a permutation cycle. Open it with one spare
    // lane, rotate values into the newly-empty lane, then close the cycle.
    const held = roots.find((node) => colOf.get(node) !== desired.get(node));
    const oldSource = colOf.get(held);
    const spare = Math.max(Math.max(...live), ...desired.values()) + 1;
    moveValue(held, spare);
    let empty = oldSource;
    while (empty !== desired.get(held)) {
      const mover = roots.find((node) => node !== held && desired.get(node) === empty);
      if (!mover) throw new Error('direct bus layout: output alignment cycle is incomplete');
      const nextEmpty = colOf.get(mover);
      moveValue(mover, empty);
      empty = nextEmpty;
    }
    moveValue(held, empty);
  }

  for (let index = 0; index < outputTargets.length; index++) {
    const col = desiredColumns[index];
    grid.placeBlock(row, col, 'output', {
      ...defaultParams('output'),
      merged: true,
      id: outputTargets[index].name,
    });
  }

  const connectivity = checkConnectivity(grid);
  if (!connectivity.wellConnected) {
    throw new Error(`direct bus layout produced an invalid diagram (${connectivity.problems[0].message})`);
  }
  if (diagnostics) Object.assign(diagnostics, {
    engine: 'direct-bus',
    alignment: {
      outputs: outputTargets.length,
      misaligned: initiallyMisaligned,
      realigned: initiallyMisaligned > 0,
      reason: outputTargets.length === 1
        ? 'cycle-safe rewiring keeps the result on the unique public data lane when identifiable'
        : 'cycle-safe rewiring aligns results with their inferred state-input lanes',
    },
  });
  return grid;
}
