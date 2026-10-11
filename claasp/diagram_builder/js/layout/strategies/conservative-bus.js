// Collision-free fallback layout for ordinary expression DAGs.
//
// The compact routers try to share routing rows.  This strategy deliberately
// does the opposite: every argument transfer owns a row, travels to a fresh
// lane immediately to the right of all live values, and crosses live vertical
// buses only with explicit double_wire blocks.  With at most one horizontal
// value on a row, unrelated horizontal routes cannot collide.
import { BLOCK_TYPES, blockWords, defaultParams } from '../../blockCatalog.js';
import { checkConnectivity } from '../../connectivity.js';
import { Grid } from '../../grid.js';

function naturalNameOrder(a, b) {
  return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
}

function paramsForCall(node) {
  const params = { ...defaultParams(node.typeName), ...node.params };
  if (['xor', 'and', 'or'].includes(node.typeName)) params.inputs = node.args.length;
  if (node.args.length === 2 && BLOCK_TYPES[node.typeName]?.params.some((p) => p.name === 'side')) {
    params.side = 'left';
  }
  // A free-text/custom operator has one catalog input because its arity is
  // unknowable in advance. Pseudocode does know the arity, so use the same
  // explicit port overrides the editor exposes for custom components.
  if (node.args.length >= 2 && BLOCK_TYPES[node.typeName]?.inputs === 1) params.portLeft = 'in';
  if (node.args.length >= 3 && BLOCK_TYPES[node.typeName]?.inputs === 1) params.portRight = 'in';
  return params;
}

export function graphToGridConservative(targetOrder, { diagnostics } = {}) {
  const seen = new Set();
  const inputs = [];
  const operations = [];

  const indexedCalls = new Map(); // call -> largest referenced tuple index
  const allCalls = new Set();
  const scanned = new Set();
  function underlyingCall(node) {
    while (node?.kind === 'named') node = node.inner;
    return node?.kind === 'call' ? node : null;
  }
  function scan(node) {
    if (node.kind === 'index') {
      const call = underlyingCall(node.of);
      if (call) indexedCalls.set(call, Math.max(indexedCalls.get(call) || 0, node.index));
      scan(node.of);
      return;
    }
    if (scanned.has(node)) return;
    scanned.add(node);
    if (node.kind === 'named') return scan(node.inner);
    if (node.kind === 'call') {
      allCalls.add(node);
      node.args.forEach(scan);
    }
  }
  targetOrder.forEach((target) => scan(target.node));

  const tupleCalls = new Set();
  for (const call of allCalls) {
    const type = BLOCK_TYPES[call.typeName];
    const catalogTuple = call.typeName !== 'free_text' && call.args.length > 1 && type?.inputs === 1
      && type.params.some((param) => param.name === 'words');
    if (catalogTuple || (indexedCalls.get(call) || 0) > 1) tupleCalls.add(call);
  }
  const tupleIndexNodes = new Map();
  function tupleIndex(call, index) {
    if (!tupleIndexNodes.has(call)) tupleIndexNodes.set(call, new Map());
    const byIndex = tupleIndexNodes.get(call);
    if (!byIndex.has(index)) byIndex.set(index, { kind: 'tuple-index', of: call, index });
    return byIndex.get(index);
  }

  function canonical(node) {
    if (node.kind === 'named' && tupleCalls.has(underlyingCall(node))) return underlyingCall(node);
    if (node.kind !== 'index') return node;
    const call = underlyingCall(node.of);
    if (call && tupleCalls.has(call)) return tupleIndex(call, node.index);
    // Some decoded one-word intermediate blocks are rendered as name[1].
    // That index is only a positional spelling, not a tuple selection.
    if (node.index === 1) return canonical(node.of);
    return node;
  }

  function visit(node) {
    node = canonical(node);
    if (seen.has(node)) return;
    seen.add(node);
    if (node.kind === 'input') {
      inputs.push(node);
      return;
    }
    if (node.kind === 'tuple-index') {
      visit(node.of);
      return;
    }
    if (node.kind === 'index') {
      throw new Error('conservative bus layout: indexed multi-word results require the general layout engine');
    }
    if (node.kind === 'named') {
      visit(node.inner);
      operations.push(node);
      return;
    }
    if (node.kind !== 'call') throw new Error(`conservative bus layout: unsupported graph node "${node.kind}"`);
    for (const arg of node.args) visit(arg);
    operations.push(node);
  }
  // Only observable outputs root the scalar circuit. Unused temporaries
  // are ordinary dead assignments, not terminal intermediate-output boxes
  // with an unconsumed bottom port. Named values reachable from outputs keep
  // their explicit intermediate boundary; native typed observer taps are
  // themselves output targets and therefore remain present.
  const observableTargets=targetOrder.filter(target=>target.isOutput);
  for (const target of observableTargets.length?observableTargets:targetOrder) visit(target.node);
  inputs.sort(naturalNameOrder);

  const argsOf = (node) => (node.kind === 'named' ? [canonical(node.inner)] : node.args.map(canonical));
  const uses = new Map();
  const addUse = (node) => uses.set(node, (uses.get(node) || 0) + 1);
  for (const node of operations) for (const arg of argsOf(node)) addUse(arg);
  for (const target of targetOrder) if (target.isOutput) addUse(canonical(target.node));

  // Indexed tuple calls are handled as wide blocks below. Other operations
  // use one output lane and therefore must fit a single-word block. Grouped
  // I/O remains straightforward: its active words are ordinary independent
  // lanes inside one wide input/output frame.
  for (const node of operations) {
    if (node.kind === 'named') continue;
    if (tupleCalls.has(node)) continue;
    if (node.args.length > 3) throw new Error(`conservative bus layout: ${node.args.length}-argument components are not representable by one block`);
    const params = paramsForCall(node);
    if (blockWords(node.typeName, params) !== 1) {
      throw new Error(`conservative bus layout: multi-word ${node.typeName} requires the general layout engine`);
    }
  }

  const grid = new Grid();
  const live = new Set();
  const colOf = new Map();
  let row = 0;
  let freshColumnFloor = 0;

  const placedInputGroups = new Set();
  let inputCol = 0;
  for (const node of inputs) {
    if (!node.wordGroup) {
      grid.placeBlock(row, inputCol, 'input', {
        ...defaultParams('input'),
        secrecy: node.secret || node.groupSecret ? 'secret' : 'public',
      });
      live.add(inputCol);
      colOf.set(node, inputCol);
      inputCol++;
      continue;
    }
    const group = node.wordGroup;
    if (placedInputGroups.has(group.groupId)) continue;
    const members = inputs
      .filter((candidate) => candidate.wordGroup?.groupId === group.groupId)
      .sort((a, b) => a.wordGroup.index - b.wordGroup.index);
    const active = members.map((member) => member.wordGroup.index);
    grid.placeBlock(row, inputCol, 'input', {
      ...defaultParams('input'),
      words: group.total,
      activeWords: active.length === group.total ? '' : active.join(','),
      secrecy: members.some((member) => member.secret || member.groupSecret) ? 'secret' : 'public',
    });
    for (const member of members) {
      const col = inputCol + member.wordGroup.index;
      live.add(col);
      colOf.set(member, col);
    }
    inputCol += group.total;
    placedInputGroups.add(group.groupId);
  }
  row++;

  function verticals(excluded = new Set()) {
    for (const col of live) {
      if (!excluded.has(col) && !grid.getBlockAt(row, col)) {
        grid.placeBlock(row, col, 'wire', { ...defaultParams('wire'), direction: 'top_to_bottom' });
      }
    }
  }

  function rightOfLive() {
    return Math.max(freshColumnFloor, live.size ? Math.max(...live) + 1 : 0);
  }

  // Copy (or, on its last use, move) a value to a new rightmost lane.
  // Exactly one horizontal route is drawn on this row.
  function deliver(node) {
    const source = colOf.get(node);
    if (source === undefined || !live.has(source)) {
      throw new Error('conservative bus layout: attempted to route a value that is no longer live');
    }
    const target = rightOfLive();
    const remaining = (uses.get(node) || 0) - 1;
    uses.set(node, remaining);
    const keepSource = remaining > 0;

    grid.placeBlock(row, source, keepSource ? 'split' : 'wire', keepSource
      ? { ...defaultParams('split'), direction: 'top_to_right_and_bottom' }
      : { ...defaultParams('wire'), direction: 'top_to_right' });
    for (let col = source + 1; col < target; col++) {
      if (live.has(col)) {
        grid.placeBlock(row, col, 'double_wire', {
          ...defaultParams('double_wire'),
          variant: 'top_to_bottom+left_to_right',
        });
      } else {
        grid.placeBlock(row, col, 'wire', { ...defaultParams('wire'), direction: 'left_to_right' });
      }
    }
    grid.placeBlock(row, target, 'wire', { ...defaultParams('wire'), direction: 'left_to_bottom' });
    verticals(new Set([source, target]));

    if (!keepSource) live.delete(source);
    live.add(target);
    row++;
    return target;
  }

  // Convergence happens in scratch lanes at the right edge. Move each new
  // result back into the leftmost free lane on one private row so scratch
  // columns are reused instead of making the diagram wider after every
  // rather than a semantic fan-out, so it does not consume a graph use.
  function compactResult(node, source) {
    let target = -1;
    for (let col = 0; col < source; col++) {
      if (!live.has(col)) {
        target = col;
        break;
      }
    }
    if (target < 0) return source;

    grid.placeBlock(row, source, 'wire', { ...defaultParams('wire'), direction: 'top_to_left' });
    for (let col = source - 1; col > target; col--) {
      if (live.has(col)) {
        grid.placeBlock(row, col, 'double_wire', {
          ...defaultParams('double_wire'),
          variant: 'top_to_bottom+right_to_left',
        });
      } else {
        grid.placeBlock(row, col, 'wire', { ...defaultParams('wire'), direction: 'right_to_left' });
      }
    }
    grid.placeBlock(row, target, 'wire', { ...defaultParams('wire'), direction: 'right_to_bottom' });
    verticals(new Set([source, target]));
    live.delete(source);
    live.add(target);
    colOf.set(node, target);
    row++;
    return target;
  }

  for (const node of operations) {
    const args = argsOf(node);
    const lanes = args.map(deliver);
    let resultCol;

    if (tupleCalls.has(node)) {
      if (lanes.length === 0) throw new Error('conservative bus layout: a tuple operation needs at least one input lane');
      const indexed = [...(tupleIndexNodes.get(node)?.entries() || [])].sort(([a], [b]) => a - b);
      if (indexed.length === 0) throw new Error('conservative bus layout: a tuple operation has no indexed result');
      const width = Math.max(lanes.length, indexed.at(-1)[0]);
      const activeInputs = Array.from({ length: lanes.length }, (_, index) => index);
      const activeOutputs = indexed.map(([index]) => index - 1);
      const params = {
        ...defaultParams(node.typeName),
        ...node.params,
        words: width,
        activeInputs: activeInputs.length === width ? '' : activeInputs.join(','),
        activeOutputs: activeOutputs.length === width ? '' : activeOutputs.join(','),
      };
      // A multi-word block has one vertical input per active word; its
      // single-word side-port arity is irrelevant and may not accept N.
      grid.placeBlock(row, lanes[0], node.typeName, params);
      verticals(new Set(lanes));
      for (const lane of lanes) live.delete(lane);
      row++;

      const tupleResults = [];
      for (const [index, indexNode] of indexed) {
        const col = lanes[0] + index - 1;
        colOf.set(indexNode, col);
        if ((uses.get(indexNode) || 0) > 0) {
          live.add(col);
          tupleResults.push(indexNode);
        }
      }
      for (const indexNode of tupleResults) compactResult(indexNode, colOf.get(indexNode));
      continue;
    } else if (node.kind === 'named') {
      resultCol = lanes[0];
      grid.placeBlock(row, resultCol, 'intermediate_output', {
        ...defaultParams('intermediate_output'),
        label: node.label,
        id: node.label,
      });
    } else if (args.length === 0) {
      resultCol = rightOfLive();
      grid.placeBlock(row, resultCol, node.typeName, paramsForCall(node));
    } else {
      const verticalIndex = args.length === 1 ? 0 : 1;
      resultCol = lanes[verticalIndex];
      grid.placeBlock(row, resultCol, node.typeName, paramsForCall(node));
      for (let i = 0; i < lanes.length; i++) {
        if (i === verticalIndex) continue;
        grid.placeBlock(row, lanes[i], 'wire', {
          ...defaultParams('wire'),
          direction: lanes[i] < resultCol ? 'top_to_right' : 'top_to_left',
        });
      }
    }

    verticals(new Set(lanes));
    for (const lane of lanes) live.delete(lane);
    colOf.set(node, resultCol);
    const resultIsLive = (uses.get(node) || 0) > 0;
    if (resultIsLive) live.add(resultCol);
    row++;
    if (resultIsLive) compactResult(node, resultCol);
  }

  const outputTargets = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  const outputLanes = [];
  const outputGroupStarts = new Map();
  for (const target of outputTargets) {
    const lane = deliver(canonical(target.node));
    outputLanes.push(lane);
    if (!target.wordGroup) continue;
    const group = target.wordGroup;
    if (!outputGroupStarts.has(group.groupId)) outputGroupStarts.set(group.groupId, lane - group.index);
    const members = outputTargets.filter((candidate) => candidate.wordGroup?.groupId === group.groupId);
    if (group.index === Math.max(...members.map((member) => member.wordGroup.index))) {
      freshColumnFloor = Math.max(freshColumnFloor, outputGroupStarts.get(group.groupId) + group.total);
    }
  }
  if (live.size !== outputLanes.length || outputLanes.some((col) => !live.has(col))) {
    throw new Error('conservative bus layout: graph contains an unterminated live value');
  }
  const placedOutputGroups = new Set();
  for (let i = 0; i < outputTargets.length; i++) {
    const target = outputTargets[i];
    if (!target.wordGroup) {
      grid.placeBlock(row, outputLanes[i], 'output', {
        ...defaultParams('output'),
        merged: true,
        id: target.name,
      });
      continue;
    }
    const group = target.wordGroup;
    if (placedOutputGroups.has(group.groupId)) continue;
    const indexed = outputTargets
      .map((candidate, index) => ({ candidate, index }))
      .filter(({ candidate }) => candidate.wordGroup?.groupId === group.groupId)
      .sort((a, b) => a.candidate.wordGroup.index - b.candidate.wordGroup.index);
    const firstLane = outputLanes[indexed[0].index];
    const active = indexed.map(({ candidate }) => candidate.wordGroup.index);
    if (!indexed.every(({ candidate, index }) => outputLanes[index] === firstLane + candidate.wordGroup.index)) {
      throw new Error('conservative bus layout: grouped output lanes are not contiguous');
    }
    grid.placeBlock(row, firstLane, 'output', {
      ...defaultParams('output'),
      words: group.total,
      activeWords: active.length === group.total ? '' : active.join(','),
      merged: true,
      id: target.name,
    });
    placedOutputGroups.add(group.groupId);
  }

  const connectivity = checkConnectivity(grid);
  if (!connectivity.wellConnected) {
    throw new Error(`conservative bus layout produced an invalid diagram (${connectivity.problems[0].message})`);
  }
  if (diagnostics) Object.assign(diagnostics, {
    engine: 'conservative-bus',
    alignment: {
      outputs: outputTargets.length,
      misaligned: outputTargets.length,
      realigned: false,
      reason: 'collision-free bus fallback prioritizes routability over input/output alignment',
    },
  });
  return grid;
}
