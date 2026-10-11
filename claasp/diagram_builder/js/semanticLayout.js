// High-level pseudocode layout patterns.  ELK remains the general fallback,
// but repeated circuit families are easier to read when their algebraic
// structure determines the drawing.  This module deliberately matches graph
// shape rather than variable names, so the same planner applies outside the
// primitive that motivated it.
import { Grid } from './grid.js';
import {
  BLOCK_TYPES, blockRowSpan, blockWords, defaultParams, resolveActiveWords, setComponentSidePort,
} from './blockCatalog.js';
import { checkConnectivity } from './connectivity.js';
import { blockRoutes } from './render.js';
import { graphToGridDirectBus } from './layout/strategies/direct-bus.js';

function unwrap(node) {
  while (node?.kind === 'named' || (node?.kind === 'index' && node.index === 1 && node.of?.kind === 'named')) {
    node = node.kind === 'named' ? node.inner : node.of.inner;
  }
  return node;
}

function isCall(node, typeName, arity) {
  node = unwrap(node);
  return node?.kind === 'call' && node.typeName === typeName && node.args.length === arity ? node : null;
}

function asInput(node) {
  node = unwrap(node);
  return node?.kind === 'input' ? node : null;
}

function naturalNameOrder(a, b) {
  return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
}

function reachableInputs(raw, into = new Set(), seen = new Set()) {
  const node = unwrap(raw);
  if (!node || seen.has(node)) return into;
  seen.add(node);
  if (node.kind === 'input') into.add(node);
  else if (node.kind === 'index') reachableInputs(node.of, into, seen);
  else if (node.kind === 'call') node.args.forEach((arg) => reachableInputs(arg, into, seen));
  return into;
}

// Recover a SIMD-style in-place update schedule from ordinary scalar calls.
// At every binary layer, one operand is used for the last time and its lane
// is replaced by the result; the other operand remains live as the carried
// lane. Equal-depth calls therefore describe parallel register updates. Once
// their interaction graph has formed equal-sized components, an edge between
// two established components marks a new phase and hence an explicit frontier
// permutation. No operation names, constants, lane counts, or primitive
// dimensions participate in the match.
function analyzeLayeredStateUpdates(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 4 || outputs.some((target) => target.wordGroup)) return null;

  const calls = new Set();
  const leaves = new Set();
  const depthMemo = new Map();
  const canonical = (raw) => unwrap(raw);
  function depth(raw) {
    const node = canonical(raw);
    if (!node) return 0;
    if (node.kind === 'input' || (node.kind === 'call' && node.args.length === 0)) {
      leaves.add(node);
      return 0;
    }
    if (node.kind !== 'call' || node.args.length < 1 || node.args.length > 2) return Number.NaN;
    if (depthMemo.has(node)) return depthMemo.get(node);
    const value = 1 + Math.max(...node.args.map(depth));
    depthMemo.set(node, value);
    calls.add(node);
    return value;
  }
  const outputRoots = outputs.map((target) => canonical(target.node));
  if (outputRoots.some((node) => !Number.isFinite(depth(node)))) return null;
  if (leaves.size !== outputs.length || calls.size < outputs.length) return null;

  const layers = new Map();
  for (const call of calls) {
    const callDepth = depthMemo.get(call);
    if (!layers.has(callDepth)) layers.set(callDepth, []);
    layers.get(callDepth).push(call);
  }
  const depths = [...layers.keys()].sort((a, b) => a - b);
  if (depths.some((value, index) => value !== index + 1)) return null;
  const groups = layers.get(depths[0])?.length;
  if (!groups || [...layers.values()].some((layer) => layer.length !== groups)) return null;
  const width = leaves.size / groups;
  if (!Number.isInteger(width) || width < 3) return null;
  for (const layer of layers.values()) {
    const first = layer[0];
    const shape = `${first.typeName}:${first.args.length}:${JSON.stringify(Object.entries(first.params).sort(([a], [b]) => a.localeCompare(b)))}`;
    if (layer.some((call) => `${call.typeName}:${call.args.length}:${JSON.stringify(Object.entries(call.params).sort(([a], [b]) => a.localeCompare(b)))}` !== shape)) return null;
  }

  const consumers = new Map();
  const addConsumer = (raw, atDepth) => {
    const node = canonical(raw);
    if (!consumers.has(node)) consumers.set(node, []);
    consumers.get(node).push(atDepth);
  };
  for (const call of calls) for (const arg of call.args) addConsumer(arg, depthMemo.get(call));
  outputRoots.forEach((root) => addConsumer(root, Number.POSITIVE_INFINITY));
  const lastUse = (node) => Math.max(...(consumers.get(node) || [-1]));

  const slotOf = new Map([...leaves].map((leaf) => [leaf, leaf]));
  const recordsByDepth = new Map();
  for (const callDepth of depths) {
    const records = [];
    const touched = new Set();
    for (const call of layers.get(callDepth)) {
      const args = call.args.map(canonical);
      if (args.some((arg) => !slotOf.has(arg))) return null;
      if (call.args.length === 1) {
        const slot = slotOf.get(args[0]);
        if (touched.has(slot) || lastUse(args[0]) !== callDepth) return null;
        touched.add(slot);
        slotOf.delete(args[0]);
        slotOf.set(call, slot);
        records.push({ call, arity: 1, slot, argument: args[0] });
        continue;
      }
      const slots = args.map((arg) => slotOf.get(arg));
      if (slots[0] === slots[1] || slots.some((slot) => touched.has(slot))) return null;
      const expiring = args.map((arg, index) => lastUse(arg) === callDepth ? index : -1).filter((index) => index >= 0);
      if (expiring.length !== 1) return null;
      const replacementIndex = expiring[0];
      const carriedIndex = 1 - replacementIndex;
      // The scalar block convention presents the vertical operand first.
      // Only Boolean commutative gates may safely reverse that convention.
      if (replacementIndex !== 0 && !['xor', 'and', 'or'].includes(call.typeName)) return null;
      const replacementSlot = slots[replacementIndex];
      const carriedSlot = slots[carriedIndex];
      touched.add(replacementSlot);
      touched.add(carriedSlot);
      slotOf.delete(args[replacementIndex]);
      slotOf.set(call, replacementSlot);
      records.push({ call, arity: 2, args, replacementIndex, replacementSlot, carriedSlot });
    }
    recordsByDepth.set(callDepth, records);
  }
  if (outputRoots.some((root) => !slotOf.has(root)) || new Set(outputRoots.map((root) => slotOf.get(root))).size !== leaves.size) return null;

  const binaryDepths = depths.filter((callDepth) => recordsByDepth.get(callDepth)[0].arity === 2);
  if (binaryDepths.length < width) return null;
  if (depths.some((callDepth) => recordsByDepth.get(callDepth).some((record) => record.arity !== recordsByDepth.get(callDepth)[0].arity))) return null;

  const makeUnion = () => {
    const parent = new Map([...leaves].map((slot) => [slot, slot]));
    const find = (slot) => parent.get(slot) === slot ? slot : (parent.set(slot, find(parent.get(slot))), parent.get(slot));
    const join = (a, b) => { a = find(a); b = find(b); if (a !== b) parent.set(b, a); };
    return { find, join };
  };
  let union = makeUnion();
  let established = null;
  const boundaryDepths = [];
  for (const callDepth of binaryDepths) {
    const records = recordsByDepth.get(callDepth);
    if (established && records.some((record) => established.get(record.replacementSlot) !== established.get(record.carriedSlot))) {
      boundaryDepths.push(callDepth);
      union = makeUnion();
      established = null;
    }
    records.forEach((record) => union.join(record.replacementSlot, record.carriedSlot));
    const components = new Map();
    for (const slot of leaves) {
      const root = union.find(slot);
      if (!components.has(root)) components.set(root, []);
      components.get(root).push(slot);
    }
    if (components.size === groups && [...components.values()].every((component) => component.length === width)) {
      established = new Map();
      [...components.values()].forEach((component, index) => component.forEach((slot) => established.set(slot, index)));
    }
  }
  if (!established) return null;

  const phaseStarts = [depths[0], ...boundaryDepths];
  const phaseEnds = [...boundaryDepths.map((value) => value - 1), depths.at(-1)];
  const orderPhase = (start, end) => {
    const edges = [];
    for (const callDepth of binaryDepths.filter((value) => value >= start && value <= end)) {
      for (const record of recordsByDepth.get(callDepth)) edges.push([record.replacementSlot, record.carriedSlot]);
    }
    const local = makeUnion();
    edges.forEach(([a, b]) => local.join(a, b));
    const components = new Map();
    for (const slot of leaves) {
      const root = local.find(slot);
      if (!components.has(root)) components.set(root, []);
      components.get(root).push(slot);
    }
    if (components.size !== groups || [...components.values()].some((component) => component.length !== width)) return null;
    const firstEdge = new Map();
    edges.forEach((edge, index) => {
      const root = local.find(edge[0]);
      if (!firstEdge.has(root)) firstEdge.set(root, { edge, index });
    });
    return [...components.entries()].sort((a, b) => firstEdge.get(a[0]).index - firstEdge.get(b[0]).index).flatMap(([root, component]) => {
      const adjacency = new Map(component.map((slot) => [slot, []]));
      for (const [a, b] of edges) if (local.find(a) === root && !adjacency.get(a).includes(b)) {
        adjacency.get(a).push(b);
        adjacency.get(b).push(a);
      }
      const [startSlot, nextSlot] = firstEdge.get(root).edge;
      const ordered = [startSlot, nextSlot];
      while (ordered.length < component.length) {
        const previous = ordered.at(-2);
        const next = adjacency.get(ordered.at(-1)).find((slot) => slot !== previous && !ordered.includes(slot));
        if (!next) break;
        ordered.push(next);
      }
      for (const slot of component) if (!ordered.includes(slot)) ordered.push(slot);
      return ordered;
    });
  };
  const phaseOrders = phaseStarts.map((start, index) => orderPhase(start, phaseEnds[index]));
  if (phaseOrders.some((order) => !order)) return null;

  const constants = [...leaves].filter((node) => node.kind === 'call');
  const inputs = [...leaves].filter((node) => node.kind === 'input').sort(naturalNameOrder);
  const sourceOrder = [...constants, ...inputs];
  const outputOrder = outputs.slice().sort(naturalNameOrder).map((target) => slotOf.get(canonical(target.node)));
  return {
    kind: 'layered-state-updates', groups, width, depths, recordsByDepth,
    phaseStarts, phaseOrders, sourceOrder, outputOrder, outputCount: outputs.length,
  };
}

function renderLayeredStateUpdates(plan) {
  const grid = new Grid();
  const columns = Array.from({ length: plan.groups * plan.width }, (_, index) => index + Math.floor(index / plan.width));
  const active = columns.join(',');
  plan.sourceOrder.forEach((source, index) => place(grid, 0, columns[index], source.kind === 'input' ? 'input' : source.typeName,
    source.kind === 'input' ? { secrecy: source.secret || source.groupSecret ? 'secret' : 'public' } : { ...source.params }));
  let row = 1;
  let physicalOrder = plan.sourceOrder.slice();
  const addPermutation = (desiredOrder) => {
    const permutation = physicalOrder.map((slot) => desiredOrder.indexOf(slot));
    if (permutation.some((destination) => destination < 0)) throw new Error('Layered state update lost a frontier slot.');
    if (!permutation.every((destination, source) => destination === source)) {
      const params = {
        permutation: permutation.join(','), words: String(columns.at(-1) + 1),
        activeInputs: active, activeOutputs: active, borders: 'invisible',
      };
      place(grid, row, 0, 'multiblockpermutation', params);
      row += blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
    }
    physicalOrder = desiredOrder.slice();
  };
  addPermutation(plan.phaseOrders[0]);
  let phaseIndex = 0;
  const columnOf = () => new Map(physicalOrder.map((slot, index) => [slot, columns[index]]));
  for (const callDepth of plan.depths) {
    if (phaseIndex + 1 < plan.phaseStarts.length && callDepth === plan.phaseStarts[phaseIndex + 1]) {
      addPermutation(plan.sourceOrder);
      columns.forEach((col) => place(grid, row, col, 'intermediate_output'));
      row++;
      phaseIndex++;
      addPermutation(plan.phaseOrders[phaseIndex]);
    }
    const records = plan.recordsByDepth.get(callDepth);
    const cols = columnOf();
    const occupied = new Set();
    if (records[0].arity === 1) {
      for (const record of records) {
        const col = cols.get(record.slot);
        place(grid, row, col, record.call.typeName, { ...record.call.params });
        occupied.add(col);
      }
    } else {
      for (const record of records) {
        const source = cols.get(record.carriedSlot);
        const target = cols.get(record.replacementSlot);
        const rightward = source < target;
        place(grid, row, source, 'split', { direction: rightward ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom' });
        occupied.add(source);
        for (let col = Math.min(source, target) + 1; col < Math.max(source, target); col++) {
          const vertical = columns.includes(col);
          place(grid, row, col, vertical ? 'double_wire' : 'wire', vertical
            ? { variant: rightward ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left' }
            : { direction: rightward ? 'left_to_right' : 'right_to_left' });
          occupied.add(col);
        }
        const params = { ...defaultParams(record.call.typeName), ...record.call.params };
        if (['xor', 'and', 'or'].includes(record.call.typeName)) params.inputs = 2;
        if (BLOCK_TYPES[record.call.typeName]?.params.some((param) => param.name === 'side')) params.side = rightward ? 'left' : 'right';
        else {
          setComponentSidePort(params, rightward ? 'left' : 'right', 'in');
          setComponentSidePort(params, rightward ? 'right' : 'left', 'off');
        }
        place(grid, row, target, record.call.typeName, params);
        occupied.add(target);
      }
    }
    columns.forEach((col) => { if (!occupied.has(col)) place(grid, row, col, 'wire'); });
    row++;
  }
  addPermutation(plan.outputOrder);
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, columns[group * plan.width], 'output', { words: plan.width, merged: false });
  }
  return grid;
}

// Discover disconnected subcircuits without knowing what construction they
// belong to. Outputs are joined when their dependency cones share an input;
// every resulting component is routed independently and packed horizontally.
// Components need not be isomorphic: global output interleaving is a
// presentation choice and should not force unrelated circuits to cross.
function analyzeIndependentComponents(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 4 || outputs.some((target) => target.wordGroup)) return null;
  const inputSets = outputs.map((target) => reachableInputs(target.node));
  const parent = outputs.map((_, index) => index);
  const find = (index) => parent[index] === index ? index : (parent[index] = find(parent[index]));
  const join = (a, b) => { a = find(a); b = find(b); if (a !== b) parent[b] = a; };
  const owner = new Map();
  inputSets.forEach((inputs, index) => {
    for (const input of inputs) {
      if (owner.has(input)) join(index, owner.get(input));
      else owner.set(input, index);
    }
  });
  const grouped = new Map();
  outputs.forEach((target, index) => {
    const root = find(index);
    if (!grouped.has(root)) grouped.set(root, []);
    grouped.get(root).push(target);
  });
  const components = [...grouped.values()].sort((a, b) => {
    const firstInput = (component) => [...component.reduce(
      (all, target) => reachableInputs(target.node, all), new Set()
    )].sort(naturalNameOrder)[0];
    return naturalNameOrder(firstInput(a), firstInput(b));
  });
  if (components.length < 2 || components.some((component) => component.length === 0)) return null;
  // Packing circuits horizontally must not renumber interleaved inputs.
  // Without a prefix permutation, only contiguous dependency cones retain
  // the declared input order; let the whole-graph bus route other cases.
  const packedInputs = components.flatMap(component => [...component.reduce(
    (all, target) => reachableInputs(target.node, all), new Set()
  )].sort(naturalNameOrder));
  const declaredInputs = [...packedInputs].sort(naturalNameOrder);
  if (packedInputs.some((input, index) => input !== declaredInputs[index])) return null;
  try {
    const grids = components.map((component) => graphToGridDirectBus(component));
    return { kind: 'independent-components', components, grids, groups: components.length, outputCount: outputs.length };
  } catch {
    return null;
  }
}

function renderIndependentComponents(plan) {
  const grid = new Grid();
  const outputRow = Math.max(...plan.grids.map((component) => component.dimensions().rows)) - 1;
  let col = 0;
  for (const component of plan.grids) {
    const outputs = component.allBlocks().filter((block) => block.type === 'output');
    grid.placeBatch(component.allBlocks().filter((block) => block.type !== 'output'), 0, col);
    for (const output of outputs) {
      for (let row = output.row; row < outputRow; row++) {
        place(grid, row, col + output.col, 'wire');
      }
      place(grid, outputRow, col + output.col, output.type, { ...output.params });
    }
    col += component.dimensions().cols + 1;
  }
  return grid;
}

function unaryPathToInput(raw) {
  const operations = [];
  let node = unwrap(raw);
  while (node?.kind === 'call' && node.args.length === 1) {
    operations.push(node);
    node = unwrap(node.args[0]);
  }
  if (node?.kind !== 'input') return null;
  operations.reverse();
  return { input: node, operations };
}

// Recognize a common state-update topology without assigning meaning to the
// operators: several lanes pass straight through to the output, copies of
// those lanes enter unary branches, the branches are reduced by commutative
// binary gates, and one remaining input is merged with that reduction.  The
// direct lanes may belong to a declared word group; grouping is presentation
// metadata and does not change the dependency proof.
function analyzeForkedReduction(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  if (outputs.length < 3) return null;
  const direct = outputs.map((target) => ({ target, input: asInput(target.node) }));
  const computed = direct.filter((record) => !record.input);
  const passthrough = direct.filter((record) => record.input);
  if (computed.length !== 1 || passthrough.length < 2) return null;
  if (new Set(passthrough.map((record) => record.input)).size !== passthrough.length) return null;

  const root = unwrap(computed[0].target.node);
  if (root?.kind !== 'call' || root.args.length !== 2 || !['xor', 'and', 'or'].includes(root.typeName)) return null;
  const passSet = new Set(passthrough.map((record) => record.input));
  let reductionRaw;
  let extraRaw;
  for (let index = 0; index < 2; index++) {
    const passDependencies = reachableInputs(root.args[index]);
    const otherDependencies = reachableInputs(root.args[1 - index]);
    if (passDependencies.size === passSet.size
        && [...passSet].every((input) => passDependencies.has(input))
        && [...otherDependencies].every((input) => !passSet.has(input))) {
      reductionRaw = root.args[index];
      extraRaw = root.args[1 - index];
      break;
    }
  }
  if (!reductionRaw) return null;
  const extra = unaryPathToInput(extraRaw);
  if (!extra || passSet.has(extra.input)) return null;

  const branches = new Map();
  const reductionCalls = [];
  const parseReduction = (raw) => {
    const chain = unaryPathToInput(raw);
    if (chain && passSet.has(chain.input)) {
      if (branches.has(chain.input)) return false;
      branches.set(chain.input, chain);
      return true;
    }
    const node = unwrap(raw);
    if (node?.kind !== 'call' || node.args.length !== 2 || !['xor', 'and', 'or'].includes(node.typeName)) return false;
    if (!parseReduction(node.args[0]) || !parseReduction(node.args[1])) return false;
    reductionCalls.push(node);
    return true;
  };
  if (!parseReduction(reductionRaw) || branches.size !== passSet.size
      || [...passSet].some((input) => !branches.has(input))) return null;

  const passInputs = passthrough.map((record) => record.input).sort(naturalNameOrder);
  return {
    kind: 'forked-reduction', outputs, computed: computed[0].target, root,
    passInputs, passTargets: new Map(passthrough.map((record) => [record.input, record.target])),
    branches, reductionCalls, reductionRoot: unwrap(reductionRaw), extra,
    outputCount: outputs.length,
  };
}

function placeGroupedInputs(grid, row, sources, columns) {
  const placed = new Set();
  for (let index = 0; index < sources.length; index++) {
    const source = sources[index];
    const group = source.wordGroup;
    if (!group) {
      place(grid, row, columns[index], 'input', {
        secrecy: source.secret || source.groupSecret ? 'secret' : 'public',
      });
      continue;
    }
    if (placed.has(group.groupId)) continue;
    const members = sources
      .map((candidate, sourceIndex) => ({ candidate, sourceIndex }))
      .filter(({ candidate }) => candidate.wordGroup?.groupId === group.groupId)
      .sort((a, b) => a.candidate.wordGroup.index - b.candidate.wordGroup.index);
    if (members.length !== group.total
        || members.some(({ candidate }, memberIndex) => candidate.wordGroup.index !== memberIndex)
        || members.some(({ sourceIndex }, memberIndex) => columns[sourceIndex] !== columns[members[0].sourceIndex] + memberIndex)) {
      throw new Error('Grouped frontier inputs must occupy one complete contiguous run.');
    }
    place(grid, row, columns[members[0].sourceIndex], 'input', {
      words: group.total,
      secrecy: members.some(({ candidate }) => candidate.secret || candidate.groupSecret) ? 'secret' : 'public',
    });
    placed.add(group.groupId);
  }
}

function placeGroupedOutputs(grid, row, outputs) {
  const placed = new Set();
  for (let index = 0; index < outputs.length; index++) {
    const target = outputs[index];
    const group = target.wordGroup;
    if (!group) {
      place(grid, row, index, 'output', { id: target.name });
      continue;
    }
    if (placed.has(group.groupId)) continue;
    const members = outputs
      .map((candidate, outputIndex) => ({ candidate, outputIndex }))
      .filter(({ candidate }) => candidate.wordGroup?.groupId === group.groupId)
      .sort((a, b) => a.candidate.wordGroup.index - b.candidate.wordGroup.index);
    if (members.length !== group.total
        || members.some(({ candidate }, memberIndex) => candidate.wordGroup.index !== memberIndex)
        || members.some(({ outputIndex }, memberIndex) => outputIndex !== members[0].outputIndex + memberIndex)) {
      throw new Error('Grouped frontier outputs must occupy one complete contiguous run.');
    }
    place(grid, row, members[0].outputIndex, 'output', {
      words: group.total, merged: true, id: members[0].candidate.name,
    });
    placed.add(group.groupId);
  }
}

function renderForkedReduction(plan) {
  const grid = new Grid();
  const count = plan.passInputs.length;
  const mainColumns = Array.from({ length: count + 1 }, (_, index) => index);
  const sources = [plan.extra.input, ...plan.passInputs];
  placeGroupedInputs(grid, 0, sources, mainColumns);

  const live = new Set(mainColumns);
  const valueColumn = new Map(sources.map((source, index) => [source, mainColumns[index]]));
  let row = 1;
  const fillLive = (occupied) => {
    for (const col of live) if (!occupied.has(col)) place(grid, row, col, 'wire');
  };

  // Copy every pass-through lane into a scratch frontier. Destinations are
  // allocated from right to left, so each new route ends before the copies
  // already established by earlier routes and no two horizontal paths share
  // a row.
  for (let index = 0; index < count; index++) {
    const source = index + 1;
    const target = 2 * count - index;
    const occupied = new Set([source, target]);
    place(grid, row, source, 'split', { direction: 'top_to_right_and_bottom' });
    for (let col = source + 1; col < target; col++) {
      place(grid, row, col, live.has(col) ? 'double_wire' : 'wire', live.has(col)
        ? { variant: 'top_to_bottom+left_to_right' }
        : { direction: 'left_to_right' });
      occupied.add(col);
    }
    place(grid, row, target, 'wire', { direction: 'left_to_bottom' });
    fillLive(occupied);
    live.add(target);
    valueColumn.set(plan.passInputs[index], target);
    row++;
  }

  const branchValueColumn = new Map();
  const maxBranchDepth = Math.max(plan.extra.operations.length,
    ...plan.passInputs.map((input) => plan.branches.get(input).operations.length));
  let extraValue = plan.extra.input;
  const branchValues = new Map(plan.passInputs.map((input) => [input, input]));
  for (let depth = 0; depth < maxBranchDepth; depth++) {
    const occupied = new Set();
    const extraOperation = plan.extra.operations[depth];
    if (extraOperation) {
      place(grid, row, 0, extraOperation.typeName, { ...extraOperation.params });
      occupied.add(0);
      extraValue = extraOperation;
    }
    plan.passInputs.forEach((input, index) => {
      const operation = plan.branches.get(input).operations[depth];
      const col = index + 1;
      if (!operation) return;
      place(grid, row, col, operation.typeName, { ...operation.params });
      occupied.add(col);
      branchValues.set(input, operation);
    });
    fillLive(occupied);
    row++;
  }
  valueColumn.set(extraValue, 0);
  plan.passInputs.forEach((input, index) => branchValueColumn.set(branchValues.get(input), index + 1));

  const reductionColumns = new Map(branchValueColumn);
  for (const call of plan.reductionCalls) {
    const args = call.args.map((arg) => unwrap(arg));
    const cols = args.map((arg) => reductionColumns.get(arg));
    if (cols.some((col) => col === undefined) || cols[0] === cols[1]) {
      throw new Error('Forked reduction lost an intermediate frontier value.');
    }
    const target = Math.min(...cols);
    const source = Math.max(...cols);
    const occupied = new Set([target, source]);
    place(grid, row, source, 'wire', { direction: 'top_to_left' });
    for (let col = source - 1; col > target; col--) {
      place(grid, row, col, live.has(col) ? 'double_wire' : 'wire', live.has(col)
        ? { variant: 'top_to_bottom+right_to_left' }
        : { direction: 'right_to_left' });
      occupied.add(col);
    }
    place(grid, row, target, call.typeName, scalarBinaryParams(call, 'right'));
    fillLive(occupied);
    live.delete(source);
    reductionColumns.set(call, target);
    row++;
  }

  const reductionColumn = reductionColumns.get(plan.reductionRoot);
  if (reductionColumn === undefined) throw new Error('Forked reduction has no final reduction lane.');
  const occupied = new Set([0, reductionColumn]);
  place(grid, row, reductionColumn, 'wire', { direction: 'top_to_left' });
  for (let col = reductionColumn - 1; col > 0; col--) {
    place(grid, row, col, live.has(col) ? 'double_wire' : 'wire', live.has(col)
      ? { variant: 'top_to_bottom+right_to_left' }
      : { direction: 'right_to_left' });
    occupied.add(col);
  }
  place(grid, row, 0, plan.root.typeName, scalarBinaryParams(plan.root, 'right'));
  fillLive(occupied);
  live.delete(reductionColumn);
  row++;

  const sourceValues = [{ value: plan.computed, col: 0 }, ...plan.passInputs.map((input) => ({
    value: plan.passTargets.get(input), col: valueColumn.get(input),
  }))].sort((a, b) => a.col - b.col);
  const outputIndex = new Map(plan.outputs.map((target, index) => [target, index]));
  const params = {
    permutation: sourceValues.map(({ value }) => outputIndex.get(value)).join(','),
    words: String(2 * count + 1),
    activeInputs: sourceValues.map(({ col }) => col).join(','),
    activeOutputs: plan.outputs.map((_, index) => index).join(','),
    borders: 'invisible',
  };
  place(grid, row, 0, 'multiblockpermutation', params);
  row += blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
  placeGroupedOutputs(grid, row, plan.outputs);
  return grid;
}

function analyzeTupleFrontierRounds(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  if (outputs.length < 4) return null;

  const indexed = new Map();
  const allCalls = new Set();
  const scanned = new Set();
  const stripNamed = (raw) => {
    let node = raw;
    while (node?.kind === 'named') node = node.inner;
    return node;
  };
  const scan = (raw) => {
    const node = stripNamed(raw);
    if (!node || scanned.has(node)) return;
    scanned.add(node);
    if (node.kind === 'index') {
      const owner = stripNamed(node.of);
      if (owner?.kind === 'call') {
        if (!indexed.has(owner)) indexed.set(owner, new Set());
        indexed.get(owner).add(node.index);
      }
      scan(node.of);
    } else if (node.kind === 'call') {
      allCalls.add(node);
      node.args.forEach(scan);
    }
  };
  targetOrder.forEach((target) => scan(target.node));
  const tupleCalls = new Set([...indexed].filter(([, indices]) => Math.max(...indices) > 1).map(([call]) => call));
  if (tupleCalls.size < 2) return null;
  const projections = new Map();
  const projection = (call, index) => {
    if (!projections.has(call)) projections.set(call, new Map());
    const byIndex = projections.get(call);
    if (!byIndex.has(index)) byIndex.set(index, { kind: 'tuple-projection', call, index });
    return byIndex.get(index);
  };
  const canonical = (raw) => {
    const node = stripNamed(raw);
    if (node?.kind !== 'index') return node;
    const owner = stripNamed(node.of);
    if (owner?.kind === 'call' && tupleCalls.has(owner)) return projection(owner, node.index);
    return node.index === 1 ? canonical(node.of) : null;
  };
  const outputValues = outputs.map((target) => canonical(target.node));
  if (outputValues.some((value) => !value) || new Set(outputValues).size !== outputs.length) return null;

  const projectionSet = (call) => {
    const indices = [...indexed.get(call)].sort((a, b) => a - b);
    if (indices.some((value, index) => value !== index + 1)) return null;
    return indices.map((value) => projection(call, value));
  };
  const traceUnary = (raw) => {
    const operations = [];
    let value = canonical(raw);
    while (value?.kind === 'call' && !tupleCalls.has(value) && value.args.length === 1) {
      operations.push(value);
      value = canonical(value.args[0]);
    }
    operations.reverse();
    return value ? { base: value, operations } : null;
  };
  const sameSet = (left, right) => left.length === right.length
    && new Set(left).size === left.length && new Set(right).size === right.length
    && left.every((value) => right.includes(value));

  const reversedRounds = [];
  let state = outputValues;
  const usedOuter = new Set();
  while (true) {
    const candidates = [...tupleCalls].filter((call) => {
      if (usedOuter.has(call)) return false;
      const values = projectionSet(call);
      return values && values.every((value) => state.includes(value));
    });
    if (candidates.length === 0) break;
    // A later state update depends on an earlier one. Prefer the candidate
    // whose projections are nearest the current outputs by selecting the
    // last call in assignment-derived reachability order.
    const callOrder = reachableCallsInAssignmentOrder(targetOrder);
    candidates.sort((a, b) => callOrder.indexOf(b) - callOrder.indexOf(a));
    const outer = candidates[0];
    const outerOutputs = projectionSet(outer);
    const resultWidth = outerOutputs.length;
    if (outer.args.length !== 2 * resultWidth) return null;
    const left = outer.args.slice(0, resultWidth).map(canonical);
    const transformed = outer.args.slice(resultWidth).map(canonical);
    if (left.some((value) => !value) || transformed.some((value) => !value)) return null;

    let transform;
    const transformOwners = [...new Set(transformed
      .filter((value) => value.kind === 'tuple-projection')
      .map((value) => value.call))];
    if (transformOwners.length === 1 && transformed.every((value) => value.kind === 'tuple-projection'
        && value.call === transformOwners[0])) {
      const call = transformOwners[0];
      const callOutputs = projectionSet(call);
      if (!sameSet(transformed, callOutputs)) return null;
      const bases = call.args.map(canonical);
      if (bases.some((value) => !value) || new Set(bases).size !== bases.length) return null;
      transform = { kind: 'tuple', call, bases, outputs: callOutputs };
    } else {
      const chains = transformed.map(traceUnary);
      if (chains.some((chain) => !chain) || chains.every((chain) => chain.operations.length === 0)) return null;
      const bases = chains.map((chain) => chain.base);
      if (new Set(bases).size !== bases.length) return null;
      transform = { kind: 'unary', chains, bases, outputs: transformed };
    }
    const previousState = [...left, ...transform.bases];
    if (new Set(previousState).size !== previousState.length
        || !sameSet(state, [...transform.bases, ...outerOutputs])) return null;
    reversedRounds.push({ outer, outerOutputs, resultWidth, left, transform, previousState, stateAfter: state });
    usedOuter.add(outer);
    state = previousState;
  }
  if (reversedRounds.length < 2 || state.some((value) => value?.kind !== 'input')) return null;
  const rounds = reversedRounds.reverse();

  const allowedCalls = new Set();
  for (const round of rounds) {
    allowedCalls.add(round.outer);
    if (round.transform.kind === 'tuple') allowedCalls.add(round.transform.call);
    else round.transform.chains.forEach((chain) => chain.operations.forEach((call) => allowedCalls.add(call)));
  }
  if ([...allCalls].some((call) => !allowedCalls.has(call))) return null;
  return {
    kind: 'tuple-frontier-rounds', outputs, outputValues, rounds,
    sources: state, width: state.length, outputCount: outputs.length,
  };
}

function renderTupleFrontierRounds(plan) {
  const grid = new Grid();
  const width = plan.width;
  const sourceColumns = Array.from({ length: width }, (_, index) => index);
  placeGroupedInputs(grid, 0, plan.sources, sourceColumns);
  let row = 1;

  for (let roundIndex = 0; roundIndex < plan.rounds.length; roundIndex++) {
    const round = plan.rounds[roundIndex];
    const baseCount = round.transform.bases.length;
    const baseStart = round.resultWidth;
    const live = new Set(sourceColumns);
    const preservedColumns = new Map();
    const fillLive = (occupied) => {
      for (const col of live) if (!occupied.has(col)) place(grid, row, col, 'wire');
    };

    for (let index = 0; index < baseCount; index++) {
      const source = baseStart + index;
      const target = width + baseCount - 1 - index;
      const occupied = new Set([source, target]);
      place(grid, row, source, 'split', { direction: 'top_to_right_and_bottom' });
      for (let col = source + 1; col < target; col++) {
        place(grid, row, col, live.has(col) ? 'double_wire' : 'wire', live.has(col)
          ? { variant: 'top_to_bottom+left_to_right' }
          : { direction: 'left_to_right' });
        occupied.add(col);
      }
      place(grid, row, target, 'wire', { direction: 'left_to_bottom' });
      fillLive(occupied);
      live.add(target);
      preservedColumns.set(round.transform.bases[index], target);
      row++;
    }

    let transformOutputColumns;
    if (round.transform.kind === 'unary') {
      const maxDepth = Math.max(...round.transform.chains.map((chain) => chain.operations.length));
      for (let depth = 0; depth < maxDepth; depth++) {
        const occupied = new Set();
        round.transform.chains.forEach((chain, index) => {
          const call = chain.operations[depth];
          if (!call) return;
          const col = baseStart + index;
          place(grid, row, col, call.typeName, { ...call.params });
          occupied.add(col);
        });
        fillLive(occupied);
        row++;
      }
      transformOutputColumns = round.transform.outputs.map((_, index) => baseStart + index);
    } else {
      const resultWidth = round.transform.outputs.length;
      const outputOffset = baseCount - resultWidth;
      const params = {
        ...round.transform.call.params,
        words: baseCount,
        activeInputs: '',
        activeOutputs: Array.from({ length: resultWidth }, (_, index) => outputOffset + index).join(','),
      };
      place(grid, row, baseStart, round.transform.call.typeName, params);
      fillLive(new Set(Array.from({ length: baseCount }, (_, index) => baseStart + index)));
      row++;
      transformOutputColumns = round.transform.outputs.map((_, index) => baseStart + outputOffset + index);
    }

    const outerInputs = [
      ...Array.from({ length: round.resultWidth }, (_, index) => index),
      ...transformOutputColumns,
    ];
    const outerOutputOffset = transformOutputColumns[0];
    const outerParams = {
      ...round.outer.params,
      words: width,
      activeInputs: outerInputs.join(','),
      activeOutputs: transformOutputColumns.join(','),
    };
    place(grid, row, 0, round.outer.typeName, outerParams);
    // The component frame occupies the entire state width even where a word
    // has no active port. Those spacer cells cannot also receive wires.
    fillLive(new Set(sourceColumns));
    row++;

    const valueColumns = new Map(preservedColumns);
    round.outerOutputs.forEach((value, index) => valueColumns.set(value, outerOutputOffset + index));
    const desired = roundIndex + 1 < plan.rounds.length
      ? plan.rounds[roundIndex + 1].previousState
      : plan.outputValues;
    const sourceValues = [...desired].map((value) => ({ value, col: valueColumns.get(value) }));
    if (sourceValues.some(({ col }) => col === undefined)) throw new Error('Tuple frontier lost a state value.');
    sourceValues.sort((a, b) => a.col - b.col);
    const destination = new Map(desired.map((value, index) => [value, index]));
    const params = {
      permutation: sourceValues.map(({ value }) => destination.get(value)).join(','),
      words: String(width + baseCount),
      activeInputs: sourceValues.map(({ col }) => col).join(','),
      activeOutputs: sourceColumns.join(','),
      borders: 'invisible',
    };
    place(grid, row, 0, 'multiblockpermutation', params);
    row += blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
    if (roundIndex + 1 < plan.rounds.length) {
      sourceColumns.forEach((col) => place(grid, row, col, 'intermediate_output'));
      row++;
    }
  }
  placeGroupedOutputs(grid, row, plan.outputs);
  return grid;
}

function analyzeTupleLanePipeline(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  const width = outputs.length;
  if (width < 2) return null;
  const indexed = new Map();
  const allCalls = new Set();
  const scanned = new Set();
  const stripNamed = (raw) => {
    let node = raw;
    while (node?.kind === 'named') node = node.inner;
    return node;
  };
  const scan = (raw) => {
    const node = stripNamed(raw);
    if (!node || scanned.has(node)) return;
    scanned.add(node);
    if (node.kind === 'index') {
      const owner = stripNamed(node.of);
      if (owner?.kind === 'call') {
        if (!indexed.has(owner)) indexed.set(owner, new Set());
        indexed.get(owner).add(node.index);
      }
      scan(node.of);
    } else if (node.kind === 'call') {
      allCalls.add(node);
      node.args.forEach(scan);
    }
  };
  targetOrder.forEach((target) => scan(target.node));
  const tupleCalls = new Set([...indexed].filter(([, indices]) => Math.max(...indices) > 1).map(([call]) => call));
  if (tupleCalls.size === 0) return null;
  const projections = new Map();
  const projection = (call, index) => {
    if (!projections.has(call)) projections.set(call, new Map());
    const byIndex = projections.get(call);
    if (!byIndex.has(index)) byIndex.set(index, { kind: 'tuple-projection', call, index });
    return byIndex.get(index);
  };
  const canonical = (raw) => {
    const node = stripNamed(raw);
    if (node?.kind !== 'index') return node;
    const owner = stripNamed(node.of);
    if (owner?.kind === 'call' && tupleCalls.has(owner)) return projection(owner, node.index);
    return node.index === 1 ? canonical(node.of) : null;
  };
  const completeProjections = (call) => {
    const indices = [...(indexed.get(call) || [])].sort((a, b) => a - b);
    if (indices.length !== width || indices.some((value, index) => value !== index + 1)) return null;
    return indices.map((index) => projection(call, index));
  };

  // Peel a lane-local chain toward its state value. Every non-state argument
  // must be a leaf input, so it can be delivered laterally without merging
  // two independently-computed subgraphs inside one lane.
  const peelLane = (raw) => {
    const reverse = [];
    let value = canonical(raw);
    while (value?.kind === 'call' && !tupleCalls.has(value)) {
      if (value.args.length < 1 || value.args.length > 2) return null;
      const args = value.args.map(canonical);
      if (args.some((arg) => !arg)) return null;
      const nonLeaves = args.map((arg, index) => arg.kind === 'input' ? -1 : index).filter((index) => index >= 0);
      if (nonLeaves.length > 1) return null;
      const continuationIndex = nonLeaves.length === 1 ? nonLeaves[0] : 0;
      const sides = args.filter((_, index) => index !== continuationIndex);
      if (sides.some((arg) => arg.kind !== 'input')) return null;
      reverse.push({ call: value, continuationIndex, sides });
      value = args[continuationIndex];
    }
    if (!value || (value.kind !== 'input' && value.kind !== 'tuple-projection')) return null;
    reverse.reverse();
    return { base: value, steps: reverse };
  };

  const suffix = outputs.map((target) => peelLane(target.node));
  if (suffix.some((chain) => !chain || chain.base.kind !== 'tuple-projection')) return null;
  const finalCall = suffix[0].base.call;
  if (suffix.some((chain, index) => chain.base.call !== finalCall || chain.base.index !== index + 1)) return null;

  const reversedStages = [];
  let current = finalCall;
  const visited = new Set();
  let sourceLanes;
  while (current) {
    if (visited.has(current) || current.args.length !== width || !completeProjections(current)) return null;
    visited.add(current);
    const chains = current.args.map(peelLane);
    if (chains.some((chain) => !chain)) return null;
    const bases = chains.map((chain) => chain.base);
    if (bases.every((base) => base.kind === 'input')) {
      if (new Set(bases).size !== width) return null;
      sourceLanes = bases;
      reversedStages.push({ call: current, chains });
      break;
    }
    if (bases.some((base) => base.kind !== 'tuple-projection')) return null;
    const previous = bases[0].call;
    if (bases.some((base, index) => base.call !== previous || base.index !== index + 1)) return null;
    reversedStages.push({ call: current, chains });
    current = previous;
  }
  if (!sourceLanes || reversedStages.length === 0) return null;
  const stages = reversedStages.reverse();
  const allowed = new Set(stages.map((stage) => stage.call));
  stages.forEach((stage) => stage.chains.forEach((chain) => chain.steps.forEach((step) => allowed.add(step.call))));
  suffix.forEach((chain) => chain.steps.forEach((step) => allowed.add(step.call)));
  if ([...allCalls].some((call) => !allowed.has(call))) return null;

  const inputs = [...new Set([...sourceLanes, ...[...allowed].flatMap((call) => call.args.map(canonical))
    .filter((value) => value?.kind === 'input')])].sort(naturalNameOrder);
  const inputIndex = new Map(inputs.map((input, index) => [input, index]));
  if (sourceLanes.some((input, index) => inputIndex.get(input) !== index)) return null;
  return {
    kind: 'tuple-lane-pipeline', width, outputs, inputs, sourceLanes, stages, suffix,
    outputCount: outputs.length,
  };
}

function renderTupleLanePipeline(plan) {
  const grid = new Grid();
  const inputColumns = plan.inputs.map((_, index) => index);
  placeGroupedInputs(grid, 0, plan.inputs, inputColumns);
  const stateColumns = Array.from({ length: plan.width }, (_, index) => index);
  const inputColumn = new Map(plan.inputs.map((input, index) => [input, index]));
  const remaining = new Map();
  const allChains = [...plan.stages.flatMap((stage) => stage.chains), ...plan.suffix];
  allChains.forEach((chain) => chain.steps.forEach((step) => step.sides.forEach((side) => {
    remaining.set(side, (remaining.get(side) || 0) + 1);
  })));
  const live = new Set(inputColumns);
  let row = 1;
  const fillLive = (occupied) => {
    for (const col of live) if (!occupied.has(col)) place(grid, row, col, 'wire');
  };

  const renderChains = (chains) => {
    const depth = Math.max(0, ...chains.map((chain) => chain.steps.length));
    for (let stepIndex = 0; stepIndex < depth; stepIndex++) {
      const entries = chains.map((chain, lane) => ({ lane, step: chain.steps[stepIndex] })).filter(({ step }) => step);
      if (entries.length === 0) continue;
      if (entries.every(({ step }) => step.sides.length === 0)) {
        const occupied = new Set();
        entries.forEach(({ lane, step }) => {
          place(grid, row, stateColumns[lane], step.call.typeName, { ...step.call.params });
          occupied.add(stateColumns[lane]);
        });
        fillLive(occupied);
        row++;
        continue;
      }
      for (const { lane, step } of entries) {
        if (step.sides.length !== 1) throw new Error('Tuple lane pipeline requires one lateral input per merged step.');
        const side = step.sides[0];
        const source = inputColumn.get(side);
        const target = stateColumns[lane];
        if (source === undefined || !live.has(source) || source === target) {
          throw new Error('Tuple lane pipeline lost a lateral input.');
        }
        const rightward = source < target;
        const uses = remaining.get(side) || 0;
        const keep = uses > 1;
        const occupied = new Set([source, target]);
        place(grid, row, source, keep ? 'split' : 'wire', keep
          ? { direction: rightward ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom' }
          : { direction: rightward ? 'top_to_right' : 'top_to_left' });
        for (let col = Math.min(source, target) + 1; col < Math.max(source, target); col++) {
          place(grid, row, col, live.has(col) ? 'double_wire' : 'wire', live.has(col)
            ? { variant: rightward ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left' }
            : { direction: rightward ? 'left_to_right' : 'right_to_left' });
          occupied.add(col);
        }
        const physicalSide = rightward ? 'left' : 'right';
        const expectedSide = step.continuationIndex === 0 ? 'right' : 'left';
        if (physicalSide !== expectedSide && !['xor', 'and', 'or'].includes(step.call.typeName)) {
          throw new Error('Tuple lane pipeline cannot reverse a non-commutative merge.');
        }
        place(grid, row, target, step.call.typeName, scalarBinaryParams(step.call, physicalSide));
        fillLive(occupied);
        remaining.set(side, uses - 1);
        if (!keep) live.delete(source);
        row++;
      }
    }
  };

  for (const stage of plan.stages) {
    renderChains(stage.chains);
    place(grid, row, 0, stage.call.typeName, { ...stage.call.params, words: plan.width });
    fillLive(new Set(stateColumns));
    row++;
  }
  renderChains(plan.suffix);
  for (const col of [...live]) if (!stateColumns.includes(col)) live.delete(col);
  placeGroupedOutputs(grid, row, plan.outputs);
  return grid;
}

// A graph containing only one-to-one input -> output references is a real
// permutation, not an empty computation. The generic lane engine used to
// order leaves by first output use and then place each output under its
// value, visually erasing the permutation altogether. Keep input and output
// orders independently stable and express the mapping with the catalog's
// ordinary rewiring component. Selection depends only on one-to-one lane
// references, so every plain lane permutation takes the same path.
function analyzePurePermutation(targetOrder) {
  if (targetOrder.length < 2 || targetOrder.some((target) => !target.isOutput || target.wordGroup)) return null;
  const records = targetOrder.map((target) => ({ target, input: asInput(target.node) }));
  if (records.some((record) => !record.input || record.input.wordGroup)) return null;
  const inputs = [...new Set(records.map((record) => record.input))].sort(naturalNameOrder);
  if (inputs.length !== records.length) return null;
  const inputIndex = new Map(inputs.map((input, index) => [input, index]));
  const outputToInput = records.map((record) => inputIndex.get(record.input));
  if (outputToInput.every((input, output) => input === output)) return null;
  const permutation = new Array(inputs.length);
  outputToInput.forEach((input, output) => { permutation[input] = output; });
  return { kind: 'pure-permutation', inputs, records, permutation, outputCount: records.length };
}

function renderPurePermutation(plan) {
  const grid = new Grid();
  plan.inputs.forEach((input, col) => place(grid, 0, col, 'input', {
    secrecy: input.secret || input.groupSecret ? 'secret' : 'public',
  }));
  const params = {
    permutation: plan.permutation.join(','),
    words: String(plan.inputs.length),
    activeInputs: '',
    activeOutputs: '',
    borders: 'invisible',
  };
  place(grid, 1, 0, 'multiblockpermutation', params);
  const outputRow = 1 + blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
  place(grid, outputRow, 0, 'output', {
    words: plan.records.length,
    merged: false,
    id: plan.records[0].target.name,
  });
  return grid;
}

function unaryChain(node) {
  const operations = [];
  node = unwrap(node);
  while (node?.kind === 'call' && node.args.length === 1) {
    operations.push(node);
    node = unwrap(node.args[0]);
  }
  if (node?.kind !== 'input') return null;
  operations.reverse(); // source -> output order
  return { input: node, operations };
}

// Independent per-lane unary pipelines are the most common regular layer in
// word-oriented primitives (rotations, S-box layers, fixed transforms). A
// topological one-operation-at-a-time walk needlessly serializes them. Draw
// equal chain depths on shared rows, then use one explicit permutation if
// the output lane order differs from the natural input order.
function analyzeParallelUnaryChains(targetOrder) {
  if (targetOrder.length < 2 || targetOrder.some((target) => !target.isOutput || target.wordGroup)) return null;
  const records = targetOrder.map((target) => ({ target, chain: unaryChain(target.node) }));
  if (records.some((record) => !record.chain || record.chain.input.wordGroup)) return null;
  if (records.every((record) => record.chain.operations.length === 0)) return null;
  const inputs = [...new Set(records.map((record) => record.chain.input))].sort(naturalNameOrder);
  if (inputs.length !== records.length) return null;
  const inputIndex = new Map(inputs.map((input, index) => [input, index]));
  const byInput = new Map(records.map((record) => [record.chain.input, record]));
  const outputToInput = records.map((record) => inputIndex.get(record.chain.input));
  const permutation = new Array(inputs.length);
  outputToInput.forEach((input, output) => { permutation[input] = output; });
  return {
    kind: 'parallel-unary-chains',
    inputs,
    records,
    byInput,
    permutation,
    maxDepth: Math.max(...records.map((record) => record.chain.operations.length)),
    outputCount: records.length,
  };
}

function renderParallelUnaryChains(plan) {
  const grid = new Grid();
  plan.inputs.forEach((input, col) => place(grid, 0, col, 'input', {
    secrecy: input.secret || input.groupSecret ? 'secret' : 'public',
  }));
  for (let depth = 0; depth < plan.maxDepth; depth++) {
    for (let col = 0; col < plan.inputs.length; col++) {
      const operation = plan.byInput.get(plan.inputs[col]).chain.operations[depth];
      if (operation) place(grid, depth + 1, col, operation.typeName, { ...operation.params, words: 1 });
      else place(grid, depth + 1, col, 'wire');
    }
  }
  let outputRow = plan.maxDepth + 1;
  if (!plan.permutation.every((output, input) => output === input)) {
    const params = {
      permutation: plan.permutation.join(','),
      words: String(plan.inputs.length),
      activeInputs: '',
      activeOutputs: '',
      borders: 'invisible',
    };
    place(grid, outputRow, 0, 'multiblockpermutation', params);
    outputRow += blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
  }
  place(grid, outputRow, 0, 'output', {
    words: plan.records.length,
    merged: false,
    id: plan.records[0].target.name,
  });
  return grid;
}

function flattenXorInputs(node, leaves = []) {
  node = unwrap(node);
  if (node?.kind === 'input') {
    leaves.push(node);
    return leaves;
  }
  if (node?.kind !== 'call' || node.typeName !== 'xor' || node.args.length !== 2) return null;
  for (const arg of node.args) if (!flattenXorInputs(arg, leaves)) return null;
  return leaves;
}

// Recognize cyclic column diffusion at word level:
// each output XORs its original lane with one correction shared by a whole
// column; every correction XORs a neighbouring column parity with a rotated
// parity from the other neighbour. This deliberately checks the complete
// algebraic shape and lane partition, not assignment or primitive names.
function analyzeCyclicColumnParity(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 9 || outputs.some((target) => target.wordGroup)) return null;
  const outputRecords = [];
  for (const target of outputs) {
    const root = isCall(target.node, 'xor', 2);
    if (!root) return null;
    const inputIndex = root.args.findIndex((arg) => asInput(arg));
    if (inputIndex < 0 || asInput(root.args[1 - inputIndex])) return null;
    outputRecords.push({ target, base: asInput(root.args[inputIndex]), correction: unwrap(root.args[1 - inputIndex]) });
  }
  const inputs = [...new Set(outputRecords.map((record) => record.base))].sort(naturalNameOrder);
  if (inputs.length !== outputRecords.length) return null;
  const corrections = [...new Set(outputRecords.map((record) => record.correction))];
  const columns = corrections.length;
  if (columns < 3 || inputs.length % columns !== 0) return null;
  const columnHeight = inputs.length / columns;
  if (!corrections.every((correction) => outputRecords.filter((record) => record.correction === correction).length === columnHeight)) return null;

  const paritySet = new Set();
  const correctionParts = new Map();
  for (const correction of corrections) {
    const xor = isCall(correction, 'xor', 2);
    if (!xor) return null;
    let rotate = null;
    let direct = null;
    for (const arg of xor.args) {
      const maybeRotate = isCall(arg, 'rotate', 1);
      if (maybeRotate) rotate = maybeRotate;
      else direct = unwrap(arg);
    }
    if (!rotate || !direct) return null;
    const rotated = unwrap(rotate.args[0]);
    const rotateParams = { ...defaultParams('rotate'), ...rotate.params };
    if (rotateParams.direction !== 'left' || Number(rotateParams.amount) !== 1) return null;
    paritySet.add(direct);
    paritySet.add(rotated);
    correctionParts.set(correction, { direct, rotated });
  }
  if (paritySet.size !== columns) return null;

  const inputIndex = new Map(inputs.map((input, index) => [input, index]));
  const parityByColumn = new Array(columns);
  const parityColumn = new Map();
  for (const parity of paritySet) {
    const leaves = flattenXorInputs(parity, []);
    if (!leaves || leaves.length !== columnHeight || new Set(leaves).size !== columnHeight) return null;
    const indices = leaves.map((leaf) => inputIndex.get(leaf));
    if (indices.some((index) => index === undefined)) return null;
    const column = Math.min(...indices);
    const expected = Array.from({ length: columnHeight }, (_, y) => y * columns + column);
    if (indices.slice().sort((a, b) => a - b).join(',') !== expected.join(',')) return null;
    if (column >= columns || parityByColumn[column]) return null;
    parityByColumn[column] = parity;
    parityColumn.set(parity, column);
  }
  if (parityByColumn.some((parity) => !parity)) return null;

  const correctionByColumn = new Array(columns);
  for (let x = 0; x < columns; x++) {
    const records = outputRecords.filter((record) => inputIndex.get(record.base) % columns === x);
    if (records.length !== columnHeight || new Set(records.map((record) => record.correction)).size !== 1) return null;
    const correction = records[0].correction;
    const parts = correctionParts.get(correction);
    if (parityColumn.get(parts.direct) !== (x + columns - 1) % columns) return null;
    if (parityColumn.get(parts.rotated) !== (x + 1) % columns) return null;
    correctionByColumn[x] = correction;
  }
  return {
    kind: 'cyclic-column-parity',
    columns,
    columnHeight,
    inputs,
    outputRecords,
    correctionByColumn,
    outputCount: inputs.length,
  };
}

function renderCyclicColumnParity(plan) {
  const grid = new Grid();
  const words = plan.inputs.length;
  const lanes = Array.from({ length: words }, (_, index) => index);
  const parityColumn = (x) => words + 3 + 2 * x;
  const directColumn = (x) => parityColumn(x) + 1;
  const dColumn = (x) => parityColumn((x + 1) % plan.columns);
  for (const col of lanes) place(grid, 0, col, 'input');
  const vertical = new Set(lanes);
  let row = 1;

  // Accumulate one parity per column while retaining all state lanes.
  for (let y = 0; y < plan.columnHeight; y++) {
    for (let x = 0; x < plan.columns; x++) {
      const source = y * plan.columns + x;
      const target = parityColumn(x);
      for (const col of [...vertical].sort((a, b) => a - b)) if (col < source || col > target) place(grid, row, col, 'wire');
      place(grid, row, source, 'split');
      for (let col = source + 1; col < target; col++) {
        place(grid, row, col, vertical.has(col) ? 'double_wire' : 'wire', vertical.has(col)
          ? { variant: 'top_to_bottom+left_to_right' }
          : { direction: 'left_to_right' });
      }
      place(grid, row, target, y === 0 ? 'wire' : 'xor', y === 0 ? { direction: 'left_to_bottom' } : {});
      vertical.add(target);
      row++;
    }
  }

  // Keep an unrotated branch beside every parity and rotate downward.
  for (const col of lanes) place(grid, row, col, 'wire');
  for (let x = 0; x < plan.columns; x++) {
    place(grid, row, parityColumn(x), 'split');
    place(grid, row, directColumn(x), 'wire', { direction: 'left_to_bottom' });
    vertical.add(directColumn(x));
  }
  row++;

  function consumeTo(source, target, intoXor) {
    const leftToRight = source < target;
    const lo = Math.min(source, target);
    const hi = Math.max(source, target);
    for (const col of [...vertical].sort((a, b) => a - b)) if (col < lo || col > hi) place(grid, row, col, 'wire');
    place(grid, row, source, 'wire', { direction: leftToRight ? 'top_to_right' : 'top_to_left' });
    for (let col = lo + 1; col < hi; col++) {
      place(grid, row, col, vertical.has(col) ? 'double_wire' : 'wire', vertical.has(col)
        ? { variant: leftToRight ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left' }
        : { direction: leftToRight ? 'left_to_right' : 'right_to_left' });
    }
    if (intoXor) place(grid, row, target, 'xor', { side: leftToRight ? 'left' : 'right' });
    else {
      place(grid, row, target, 'wire', { direction: leftToRight ? 'left_to_bottom' : 'right_to_bottom' });
      vertical.add(target);
    }
    vertical.delete(source);
    row++;
  }

  for (let x = 0; x < plan.columns; x++) {
    const target = dColumn(x);
    for (const col of [...vertical].sort((a, b) => a - b)) {
      place(grid, row, col, col === target ? 'rotate' : 'wire', col === target ? { direction: 'left', amount: 1 } : {});
    }
    row++;
    consumeTo(directColumn((x + plan.columns - 1) % plan.columns), target, true);
  }

  // Broadcast each correction back into the matching state column.
  for (let x = 0; x < plan.columns; x++) {
    const source = dColumn(x);
    for (let y = plan.columnHeight - 1; y >= 0; y--) {
      const target = y * plan.columns + x;
      for (const col of [...vertical].sort((a, b) => a - b)) if (col < target || col > source) place(grid, row, col, 'wire');
      place(grid, row, source, y === 0 ? 'wire' : 'split', {
        direction: y === 0 ? 'top_to_left' : 'top_to_left_and_bottom',
      });
      for (let col = target + 1; col < source; col++) {
        place(grid, row, col, vertical.has(col) ? 'double_wire' : 'wire', vertical.has(col)
          ? { variant: 'top_to_bottom+right_to_left' }
          : { direction: 'right_to_left' });
      }
      place(grid, row, target, 'xor', { side: 'right' });
      if (y === 0) vertical.delete(source);
      row++;
    }
  }
  place(grid, row, 0, 'output', { words, merged: false });
  return grid;
}

function analyzeRotatedParityRing(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 6 || outputs.some((target) => target.wordGroup)) return null;
  const records = [];
  for (const target of outputs) {
    const root = isCall(target.node, 'xor', 2);
    if (!root) return null;
    const baseIndex = root.args.findIndex((arg) => asInput(arg));
    if (baseIndex < 0 || asInput(root.args[1 - baseIndex])) return null;
    records.push({ target, base: asInput(root.args[baseIndex]), correction: unwrap(root.args[1 - baseIndex]) });
  }
  const inputs = [...new Set(records.map((record) => record.base))].sort(naturalNameOrder);
  if (inputs.length !== records.length) return null;
  const corrections = [...new Set(records.map((record) => record.correction))];
  const groups = corrections.length;
  if (groups < 3 || inputs.length % groups !== 0) return null;
  const groupSize = inputs.length / groups;
  const inputIndex = new Map(inputs.map((input, index) => [input, index]));
  const parityGroup = new Map();
  const correctionParity = new Map();
  let rotationSignature = null;
  let rotationParams = null;
  for (const correction of corrections) {
    const xor = isCall(correction, 'xor', 2);
    if (!xor) return null;
    const rotates = xor.args.map((arg) => isCall(arg, 'rotate', 1));
    if (rotates.some((rotate) => !rotate)) return null;
    const params = rotates.map((rotate) => ({ ...defaultParams('rotate'), ...rotate.params }));
    const signature = params
      .map((param) => `${param.direction}:${Number(param.amount)}`)
      .sort()
      .join('|');
    if (rotationSignature === null) {
      rotationSignature = signature;
      rotationParams = params.slice().sort((a, b) => Number(a.amount) - Number(b.amount));
    }
    else if (signature !== rotationSignature) return null;
    const parities = rotates.map((rotate) => unwrap(rotate.args[0]));
    if (parities[0] !== parities[1]) return null;
    const parity = parities[0];
    const leaves = flattenXorInputs(parity, []);
    if (!leaves || leaves.length !== groupSize || new Set(leaves).size !== groupSize) return null;
    const indices = leaves.map((leaf) => inputIndex.get(leaf)).sort((a, b) => a - b);
    const group = Math.floor(indices[0] / groupSize);
    const expected = Array.from({ length: groupSize }, (_, index) => group * groupSize + index);
    if (indices.join(',') !== expected.join(',')) return null;
    parityGroup.set(parity, group);
    correctionParity.set(correction, parity);
  }
  for (let group = 0; group < groups; group++) {
    const groupRecords = records.filter((record) => Math.floor(inputIndex.get(record.base) / groupSize) === group);
    if (groupRecords.length !== groupSize || new Set(groupRecords.map((record) => record.correction)).size !== 1) return null;
    const parity = correctionParity.get(groupRecords[0].correction);
    if (parityGroup.get(parity) !== (group + groups - 1) % groups) return null;
  }
  const recordByBase = new Map(records.map((record) => [record.base, record]));
  return {
    kind: 'rotated-parity-ring', groups, groupSize, rotationParams, inputs,
    physicalOutputs: inputs.map((input) => recordByBase.get(input).target), outputCount: outputs.length,
  };
}

function renderRotatedParityRing(plan) {
  const grid = new Grid();
  const stride = plan.groupSize + 2;
  const stateCol = (group, index) => stride * group + index;
  const parityCol = (group) => stride * group + plan.groupSize;
  const branchCol = (group) => parityCol(group) + 1;
  const state = [];
  for (let group = 0; group < plan.groups; group++) for (let index = 0; index < plan.groupSize; index++) state.push(stateCol(group, index));
  for (const col of state) place(grid, 0, col, 'input');

  for (let step = 0; step < plan.groupSize; step++) {
    const sourceIndex = plan.groupSize - 1 - step;
    for (let group = 0; group < plan.groups; group++) {
      const source = stateCol(group, sourceIndex);
      const target = parityCol(group);
      for (let index = 0; index < plan.groupSize; index++) {
        const col = stateCol(group, index);
        if (col < source) place(grid, step + 1, col, 'wire');
        else if (col === source) place(grid, step + 1, col, 'split');
        else place(grid, step + 1, col, 'double_wire', { variant: 'top_to_bottom+left_to_right' });
      }
      place(grid, step + 1, target, step === 0 ? 'wire' : 'xor', step === 0 ? { direction: 'left_to_bottom' } : { side: 'left' });
    }
  }
  let row = plan.groupSize + 1;
  for (const col of state) place(grid, row, col, 'wire');
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, parityCol(group), 'split');
    place(grid, row, branchCol(group), 'wire', { direction: 'left_to_bottom' });
  }
  row++;
  for (const col of state) place(grid, row, col, 'wire');
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, parityCol(group), 'rotate', { ...plan.rotationParams[0] });
    place(grid, row, branchCol(group), 'rotate', { ...plan.rotationParams[1] });
  }
  row++;
  for (const col of state) place(grid, row, col, 'wire');
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, parityCol(group), 'xor', { side: 'right' });
    place(grid, row, branchCol(group), 'wire', { direction: 'top_to_left' });
  }
  row++;

  // Rotate the correction lanes by one group using two parallel crossing
  // rows; each turning double-wire forwards one correction while receiving
  // the previous group into its own downward lane.
  for (const col of state) place(grid, row, col, col < stride ? 'wire' : 'double_wire', col < stride ? {} : { variant: 'top_to_bottom+left_to_right' });
  place(grid, row, parityCol(0), 'wire', { direction: 'top_to_right' });
  place(grid, row, branchCol(0), 'wire', { direction: 'left_to_right' });
  for (let group = 1; group < plan.groups; group++) {
    place(grid, row, parityCol(group), 'double_wire', { variant: 'top_to_right+left_to_bottom', borders: 'visible' });
    place(grid, row, branchCol(group), group === plan.groups - 1 ? 'wire' : 'wire', {
      direction: group === plan.groups - 1 ? 'left_to_bottom' : 'left_to_right',
    });
  }
  row++;
  for (let index = 0; index < plan.groupSize; index++) place(grid, row, stateCol(0, index), 'wire');
  place(grid, row, parityCol(0), 'wire', { direction: 'right_to_bottom' });
  for (let col = parityCol(0) + 1; col < branchCol(plan.groups - 1); col++) {
    if (state.includes(col) || Array.from({ length: plan.groups - 1 }, (_, group) => parityCol(group + 1)).includes(col)) {
      place(grid, row, col, 'double_wire', { variant: 'top_to_bottom+right_to_left' });
    } else {
      place(grid, row, col, 'wire', { direction: 'right_to_left' });
    }
  }
  place(grid, row, branchCol(plan.groups - 1), 'wire', { direction: 'top_to_left' });
  row++;

  for (let step = 0; step < plan.groupSize; step++) {
    const targetIndex = plan.groupSize - 1 - step;
    for (let group = 0; group < plan.groups; group++) {
      for (let index = 0; index < plan.groupSize; index++) {
        const col = stateCol(group, index);
        if (index < targetIndex) place(grid, row, col, 'wire');
        else if (index === targetIndex) place(grid, row, col, 'xor', { side: 'right' });
        else place(grid, row, col, 'double_wire', { variant: 'top_to_bottom+right_to_left' });
      }
      place(grid, row, parityCol(group), step === plan.groupSize - 1 ? 'wire' : 'split', {
        direction: step === plan.groupSize - 1 ? 'top_to_left' : 'top_to_left_and_bottom',
      });
    }
    row++;
  }
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, stateCol(group, 0), 'output', { words: plan.groupSize, merged: false });
  }
  return grid;
}

function analyzeParallelForkJoin(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 2 || outputs.length !== targetOrder.length || outputs.some((target) => target.wordGroup)) return null;
  const records = [];
  for (const target of outputs) {
    const root = unwrap(target.node);
    if (root?.kind !== 'call' || root.args.length !== 3) return null;
    const direct = root.args.map((arg, index) => ({ arg: unwrap(arg), index })).filter(({ arg }) => arg.kind === 'input');
    if (direct.length !== 1) return null;
    const base = direct[0].arg;
    const branches = [];
    for (let index = 0; index < 3; index++) {
      if (index === direct[0].index) { branches.push(null); continue; }
      const branch = unwrap(root.args[index]);
      if (branch?.kind !== 'call' || branch.args.length !== 1 || asInput(branch.args[0]) !== base) return null;
      branches.push(branch);
    }
    records.push({ target, root, base, branches, directIndex: direct[0].index });
  }
  if (!records.every((record) => record.directIndex === 1)) return null;
  const inputs = records.map((record) => record.base);
  if (new Set(inputs).size !== inputs.length) return null;
  if (inputs.slice().sort(naturalNameOrder).some((input, index) => input !== records[index].base)) return null;
  return { kind: 'parallel-fork-join', records, outputCount: outputs.length };
}

function renderParallelForkJoin(plan) {
  const grid = new Grid();
  for (let index = 0; index < plan.records.length; index++) place(grid, 0, 3 * index + 1, 'input');
  for (let index = 0; index < plan.records.length; index++) {
    const center = 3 * index + 1;
    place(grid, 1, center, 'split', { direction: 'top_to_left_and_right_and_bottom' });
    place(grid, 1, center - 1, 'wire', { direction: 'right_to_bottom' });
    place(grid, 1, center + 1, 'wire', { direction: 'left_to_bottom' });
  }
  for (let index = 0; index < plan.records.length; index++) {
    const center = 3 * index + 1;
    const record = plan.records[index];
    place(grid, 2, center - 1, record.branches[0].typeName, record.branches[0].params);
    place(grid, 2, center, 'wire');
    place(grid, 2, center + 1, record.branches[2].typeName, record.branches[2].params);
  }
  for (let index = 0; index < plan.records.length; index++) {
    const center = 3 * index + 1;
    const record = plan.records[index];
    place(grid, 3, center - 1, 'wire', { direction: 'top_to_right' });
    place(grid, 3, center, record.root.typeName, { ...record.root.params, inputs: 3 });
    place(grid, 3, center + 1, 'wire', { direction: 'top_to_left' });
  }
  for (let index = 0; index < plan.records.length; index++) place(grid, 4, 3 * index + 1, 'output');
  return grid;
}

function analyzeSerialWideTransforms(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  const width = outputs.length;
  if (width < 2 || outputs.some((target) => target.wordGroup)) return null;
  const projected = outputs.map((target) => unwrap(target.node));
  if (projected.some((node) => node?.kind !== 'index' || node.of?.kind !== 'call')) return null;
  let current = projected[0].of;
  if (projected.some((node) => node.of !== current)) return null;
  const outputPermutation = projected.map((node) => node.index - 1);
  const layers = [];
  while (current?.kind === 'call' && current.typeName === 'free_text' && current.args.length === width) {
    layers.unshift(current);
    const args = current.args.map(unwrap);
    if (args.every((arg) => arg?.kind === 'input')) break;
    if (args.some((arg) => arg?.kind !== 'index' || arg.of?.kind !== 'call')) return null;
    const previous = args[0].of;
    if (args.some((arg) => arg.of !== previous)) return null;
    current = previous;
  }
  if (layers.length < 2 || layers.length > 8) return null;
  const firstArgs = layers[0].args.map(unwrap);
  if (firstArgs.some((arg) => arg?.kind !== 'input') || new Set(firstArgs).size !== width) return null;
  const text = layers[0].params.text;
  if (!text || layers.some((layer) => layer.params.text !== text)) return null;
  const permutations = [];
  for (let index = 1; index < layers.length; index++) {
    const args = layers[index].args.map(unwrap);
    if (args.some((arg) => arg?.kind !== 'index' || arg.of !== layers[index - 1])) return null;
    permutations.push(args.map((arg) => arg.index - 1));
  }
  return {
    kind: 'serial-wide-transforms', width, layers: layers.length, text,
    permutations: permutations.map(inversePermutation),
    outputPermutation: inversePermutation(outputPermutation),
  };
}

function renderSerialWideTransforms(plan) {
  const grid = new Grid();
  const activeColumns = Array.from({ length: plan.width }, (_, index) => index);
  const active = activeColumns.join(',');
  activeColumns.forEach((col) => place(grid, 0, col, 'input'));
  let row = 1;
  for (let index = 0; index < plan.layers; index++) {
    place(grid, row++, 0, 'free_text', {
      words: plan.width, text: plan.text, activeInputs: active, activeOutputs: active,
    });
    if (index < plan.layers - 1) {
      const permutation = plan.permutations[index];
      if (!permutation.every((value, lane) => value === lane)) {
        place(grid, row, 0, 'multiblockpermutation', {
          permutation: permutation.join(','), words: String(plan.width), activeInputs: active,
          activeOutputs: active, borders: 'invisible',
        });
        row += 2;
      }
      activeColumns.forEach((col) => place(grid, row, col, 'intermediate_output'));
      row++;
    }
  }
  if (!plan.outputPermutation.every((value, lane) => value === lane)) {
    place(grid, row, 0, 'multiblockpermutation', {
      permutation: plan.outputPermutation.join(','), words: String(plan.width), activeInputs: active,
      activeOutputs: active, borders: 'invisible',
    });
    row += 2;
  }
  place(grid, row, 0, 'output', { words: plan.width, merged: false });
  return grid;
}

function inversePermutation(destinationSources) {
  const permutation = new Array(destinationSources.length);
  destinationSources.forEach((source, destination) => { permutation[source] = destination; });
  return permutation;
}

// A data-driven two-stage SIMD pipeline:
//
//   independent unary input chains -> G M-input calls -> permutation
//   -> G M-input calls -> output permutation
//
// The widths, groups, call types, unary operations, and both permutations
// are all recovered from tuple projections. This covers byte/word-oriented
// substitution-permutation layers without knowing a state geometry.
function analyzeParallelGroupedPipeline(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 4 || outputs.some((target) => target.wordGroup)) return null;
  const projections = outputs.map((target) => unwrap(target.node));
  if (projections.some((node) => node?.kind !== 'index' || node.of?.kind !== 'call')) return null;
  const finalCalls = [];
  for (const projection of projections) if (!finalCalls.includes(projection.of)) finalCalls.push(projection.of);
  const groups = finalCalls.length;
  if (groups < 2 || outputs.length % groups !== 0) return null;
  const width = outputs.length / groups;
  if (width < 2 || finalCalls.some((call) => call.args.length !== width || call.typeName !== finalCalls[0].typeName)) return null;

  const middleProjections = finalCalls.flatMap((call) => call.args.map(unwrap));
  if (middleProjections.some((node) => node?.kind !== 'index' || node.of?.kind !== 'call')) return null;
  const middleCalls = [];
  for (const projection of middleProjections) if (!middleCalls.includes(projection.of)) middleCalls.push(projection.of);
  if (middleCalls.length !== groups
      || middleCalls.some((call) => call.args.length !== width || call.typeName !== middleCalls[0].typeName)) return null;

  const completeProjectionSet = (nodes, calls) => {
    const keys = nodes.map((node) => `${calls.indexOf(node.of)}:${node.index}`);
    return nodes.every((node) => calls.includes(node.of) && node.index >= 1 && node.index <= width)
      && new Set(keys).size === groups * width;
  };
  if (!completeProjectionSet(projections, finalCalls)
      || !completeProjectionSet(middleProjections, middleCalls)) return null;

  const chains = middleCalls.flatMap((call) => call.args.map(unaryChain));
  if (chains.some((chain) => !chain || chain.input.wordGroup)) return null;
  const inputs = chains.map((chain) => chain.input);
  if (new Set(inputs).size !== groups * width) return null;
  const naturalInputs = [...inputs].sort(naturalNameOrder);
  const inputIndex = new Map(naturalInputs.map((input, index) => [input, index]));
  const middleDestinationSources = chains.map((chain) => inputIndex.get(chain.input));

  const middleIndex = new Map(middleCalls.map((call, index) => [call, index]));
  const finalDestinationSources = middleProjections.map((node) =>
    middleIndex.get(node.of) * width + node.index - 1);
  const finalIndex = new Map(finalCalls.map((call, index) => [call, index]));
  const outputDestinationSources = projections.map((node) =>
    finalIndex.get(node.of) * width + node.index - 1);
  return {
    kind: 'parallel-grouped-pipeline', groups, width, inputs: naturalInputs,
    chainsByInput: new Map(chains.map((chain) => [chain.input, chain])),
    maxUnaryDepth: Math.max(0, ...chains.map((chain) => chain.operations.length)),
    middleCalls, finalCalls,
    middlePermutation: inversePermutation(middleDestinationSources),
    finalPermutation: inversePermutation(finalDestinationSources),
    outputPermutation: inversePermutation(outputDestinationSources),
    outputCount: outputs.length,
  };
}

function renderParallelGroupedPipeline(plan) {
  const grid = new Grid();
  const total = plan.groups * plan.width;
  plan.inputs.forEach((input, col) => place(grid, 0, col, 'input', {
    secrecy: input.secret || input.groupSecret ? 'secret' : 'public',
  }));
  let row = 1;
  for (let depth = 0; depth < plan.maxUnaryDepth; depth++, row++) {
    plan.inputs.forEach((input, col) => {
      const operation = plan.chainsByInput.get(input).operations[depth];
      place(grid, row, col, operation?.typeName ?? 'wire', operation ? { ...operation.params, words: 1 } : {});
    });
  }
  const addPermutation = (values) => {
    if (values.every((destination, source) => destination === source)) return;
    const params = {
      permutation: values.join(','), words: String(total), activeInputs: '', activeOutputs: '', borders: 'invisible',
    };
    place(grid, row, 0, 'multiblockpermutation', params);
    row += blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
  };
  const addCalls = (calls) => {
    calls.forEach((call, group) => place(grid, row, group * plan.width, call.typeName, {
      ...call.params, words: plan.width,
    }));
    row++;
  };
  addPermutation(plan.middlePermutation);
  addCalls(plan.middleCalls);
  addPermutation(plan.finalPermutation);
  addCalls(plan.finalCalls);
  addPermutation(plan.outputPermutation);
  place(grid, row, 0, 'output', { words: total, merged: false });
  return grid;
}

function callShapeKey(call) {
  return `${call.typeName}:${JSON.stringify(Object.entries(call.params).sort(([a], [b]) => a.localeCompare(b)))}`;
}

// Discover G parallel M-word transforms, an arbitrary re-grouping, and G
// further M-word transforms.  G and M are inferred from tuple projections;
// neither the primitive nor a conventional state shape is known here.
function analyzeParallelWideDoubleRound(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length < 4 || outputs.some((target) => target.wordGroup)) return null;
  const projections = outputs.map((target) => unwrap(target.node));
  if (projections.some((node) => node?.kind !== 'index' || node.of?.kind !== 'call')) return null;
  const finalCalls = [];
  for (const projection of projections) if (!finalCalls.includes(projection.of)) finalCalls.push(projection.of);
  const groups = finalCalls.length;
  if (groups < 2 || outputs.length % groups !== 0) return null;
  const width = outputs.length / groups;
  if (width < 2 || finalCalls.some((call) => call.typeName !== 'free_text' || call.args.length !== width)) return null;
  const finalShape = callShapeKey(finalCalls[0]);
  if (finalCalls.some((call) => callShapeKey(call) !== finalShape)) return null;
  const firstProjections = finalCalls.flatMap((call) => call.args.map(unwrap));
  if (firstProjections.some((node) => node?.kind !== 'index' || node.of?.kind !== 'call')) return null;
  const firstCalls = [];
  for (const projection of firstProjections) if (!firstCalls.includes(projection.of)) firstCalls.push(projection.of);
  if (firstCalls.length !== groups || firstCalls.some((call) => call.typeName !== 'free_text' || call.args.length !== width)) return null;
  const firstShape = callShapeKey(firstCalls[0]);
  if (firstCalls.some((call) => callShapeKey(call) !== firstShape)) return null;
  if (firstProjections.some((node) => !firstCalls.includes(node.of))) return null;
  const validProjectionSet = (nodes, calls) => {
    const keys = nodes.map((node) => `${calls.indexOf(node.of)}:${node.index}`);
    return nodes.every((node) => node.index >= 1 && node.index <= width)
      && new Set(keys).size === groups * width;
  };
  if (!validProjectionSet(projections, finalCalls) || !validProjectionSet(firstProjections, firstCalls)) return null;
  const leaves = firstCalls.flatMap((call) => call.args.map(unwrap));
  if (leaves.some((node) => node?.kind !== 'input' && !(node?.kind === 'call' && node.typeName === 'constant' && node.args.length === 0))) return null;
  if (new Set(leaves).size !== groups * width || new Set([...firstCalls, ...finalCalls]).size !== 2 * groups) return null;
  const preferredSources = [];
  for (let argument = 0; argument < width; argument++) {
    for (const call of firstCalls) preferredSources.push(unwrap(call.args[argument]));
  }
  // Input numbering is positional when a generated grid is read back. Keep
  // input leaves in natural order while retaining the argument-major slots
  // preferred by the drawing; constants remain in their discovered slots.
  const orderedInputs = preferredSources.filter((node) => node.kind === 'input').sort(naturalNameOrder);
  let nextInput = 0;
  const topSources = preferredSources.map((node) => node.kind === 'input' ? orderedInputs[nextInput++] : node);
  const callMajorIndex = new Map();
  firstCalls.forEach((call, callIndex) => call.args.forEach((raw, argument) => {
    callMajorIndex.set(unwrap(raw), callIndex * width + argument);
  }));
  const toCallGroups = topSources.map((source) => callMajorIndex.get(source));
  if (toCallGroups.some((destination) => destination === undefined)) return null;
  const fromCallGroups = inversePermutation(toCallGroups);
  const firstIndex = new Map(firstCalls.map((call, index) => [call, index]));
  const diagonalDestinationSources = finalCalls.flatMap((call) => call.args.map((raw) => {
    const node = unwrap(raw);
    return fromCallGroups[firstIndex.get(node.of) * width + node.index - 1];
  }));
  const finalIndex = new Map(finalCalls.map((call, index) => [call, index]));
  const outputDestinationSources = projections.map((node) => width * finalIndex.get(node.of) + node.index - 1);
  return {
    kind: 'parallel-wide-double-round', groups, width, topSources,
    firstType: firstCalls[0].typeName, firstParams: firstCalls[0].params,
    finalType: finalCalls[0].typeName, finalParams: finalCalls[0].params,
    toCallGroups,
    diagonalPermutation: inversePermutation(diagonalDestinationSources),
    outputPermutation: inversePermutation(outputDestinationSources),
  };
}

function renderParallelWideDoubleRound(plan) {
  const grid = new Grid();
  const columns = Array.from({ length: plan.groups * plan.width }, (_, index) =>
    index + Math.floor(index / plan.width));
  const active = columns.join(',');
  plan.topSources.forEach((source, index) => {
    const params = source.kind === 'input'
      ? { secrecy: source.secret || source.groupSecret ? 'secret' : 'public' }
      : { ...source.params };
    place(grid, 0, columns[index], source.kind === 'input' ? 'input' : 'constant', params);
  });
  const physicalWidth = columns.at(-1) + 1;
  let row = 1;
  const permutation = (values) => {
    const block = place(grid, row, 0, 'multiblockpermutation', {
      permutation: values.join(','), words: String(physicalWidth), activeInputs: active,
      activeOutputs: active, borders: 'invisible',
    });
    row += blockRowSpan(block.type, block.params);
  };
  permutation(plan.toCallGroups);
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, group * (plan.width + 1), plan.firstType, { ...plan.firstParams, words: plan.width });
  }
  row++;
  permutation(inversePermutation(plan.toCallGroups));
  columns.forEach((col) => place(grid, row, col, 'intermediate_output'));
  row++;
  permutation(plan.diagonalPermutation);
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, group * (plan.width + 1), plan.finalType, { ...plan.finalParams, words: plan.width });
  }
  row++;
  permutation(plan.outputPermutation);
  for (let group = 0; group < plan.groups; group++) {
    place(grid, row, group * (plan.width + 1), 'output', { words: plan.width, merged: false });
  }
  return grid;
}

function matchTransformMergeBranch(node) {
  const root = isCall(node, 'xor', 2);
  if (!root) return null;
  for (let inputIndex = 0; inputIndex < 2; inputIndex++) {
    const direct = asInput(root.args[inputIndex]);
    const transform = isCall(root.args[1 - inputIndex], 'free_text', 1);
    const transformed = transform && asInput(transform.args[0]);
    if (direct && transformed) return { root, direct, transformed, transform };
  }
  return null;
}

function analyzeTwoBranchTransformMerge(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput);
  if (outputs.length !== 2) return null;
  const firstInput = asInput(outputs[0].node);
  const secondBranch = matchTransformMergeBranch(outputs[1].node);
  if (firstInput && secondBranch && secondBranch.transformed === firstInput && secondBranch.direct !== firstInput) {
    return {
      kind: 'two-branch-transform-merge', alternating: false, grouped: Boolean(firstInput.wordGroup),
      inputs: [secondBranch.direct, firstInput], text: secondBranch.transform.params.text,
    };
  }
  const firstBranch = matchTransformMergeBranch(outputs[0].node);
  const secondRoot = isCall(outputs[1].node, 'xor', 2);
  if (!firstBranch || !secondRoot) return null;
  for (let inputIndex = 0; inputIndex < 2; inputIndex++) {
    const direct = asInput(secondRoot.args[inputIndex]);
    const transform = isCall(secondRoot.args[1 - inputIndex], 'free_text', 1);
    if (!direct || !transform || unwrap(transform.args[0]) !== unwrap(outputs[0].node)
        || direct !== firstBranch.transformed) continue;
    return {
      kind: 'two-branch-transform-merge', alternating: true, grouped: Boolean(direct.wordGroup),
      inputs: [firstBranch.direct, direct], texts: [firstBranch.transform.params.text, transform.params.text],
    };
  }
  return null;
}

// Recognize a symmetric two-lane construction in which the lanes are first
// reduced into one middle value, that value passes through a unary pipeline,
// and the result is forked back into one merge per original lane. The match
// uses only sharing and arity; it does not depend on Lai-Massey, F, XOR, or
// any variable name.
function analyzeSharedMiddleFork(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  if (outputs.length !== 2 || outputs.some((target) => target.wordGroup)) return null;
  const commutative = new Set(['xor', 'and', 'or']);
  const records = [];
  for (const target of outputs) {
    const root = unwrap(target.node);
    if (root?.kind !== 'call' || root.args.length !== 2 || !commutative.has(root.typeName)) return null;
    const direct = root.args.map((arg, index) => ({ input: asInput(arg), index }))
      .filter(({ input }) => input);
    if (direct.length !== 1) return null;
    records.push({ target, root, direct: direct[0].input, shared: unwrap(root.args[1 - direct[0].index]) });
  }
  if (records[0].direct === records[1].direct || records[0].shared !== records[1].shared) return null;

  const operations = [];
  let reduction = records[0].shared;
  while (reduction?.kind === 'call' && reduction.args.length === 1) {
    operations.push(reduction);
    reduction = unwrap(reduction.args[0]);
  }
  if (operations.length === 0 || reduction?.kind !== 'call' || reduction.args.length !== 2
      || !commutative.has(reduction.typeName)) return null;
  const reducedInputs = reduction.args.map(asInput);
  if (reducedInputs.some((input) => !input)
      || new Set(reducedInputs).size !== 2
      || records.some((record) => !reducedInputs.includes(record.direct))) return null;

  const inputs = [...reducedInputs].sort(naturalNameOrder);
  const byInput = new Map(records.map((record) => [record.direct, record]));
  return { kind: 'shared-middle-fork', inputs, byInput, reduction, operations: operations.reverse(), outputCount: 2 };
}

function renderSharedMiddleFork(plan) {
  const grid = new Grid();
  place(grid, 0, 0, 'input', { secrecy: plan.inputs[0].secret ? 'secret' : 'public' });
  place(grid, 0, 2, 'input', { secrecy: plan.inputs[1].secret ? 'secret' : 'public' });
  place(grid, 1, 0, 'split', { direction: 'top_to_right_and_bottom' });
  place(grid, 1, 1, plan.reduction.typeName, {
    ...plan.reduction.params,
    inputs: 2,
    portLeft: 'in', portRight: 'in', portTop: 'off', portBottom: 'out',
  });
  place(grid, 1, 2, 'split', { direction: 'top_to_left_and_bottom' });
  let row = 2;
  for (const operation of plan.operations) {
    place(grid, row, 0, 'wire');
    place(grid, row, 1, operation.typeName, { ...operation.params });
    place(grid, row, 2, 'wire');
    row++;
  }
  place(grid, row, 0, plan.byInput.get(plan.inputs[0]).root.typeName, {
    ...plan.byInput.get(plan.inputs[0]).root.params, inputs: 2, side: 'right',
  });
  place(grid, row, 1, 'split', { direction: 'top_to_left_and_right' });
  place(grid, row, 2, plan.byInput.get(plan.inputs[1]).root.typeName, {
    ...plan.byInput.get(plan.inputs[1]).root.params, inputs: 2, side: 'left',
  });
  row++;
  place(grid, row, 0, 'output', { id: plan.byInput.get(plan.inputs[0]).target.name });
  place(grid, row, 2, 'output', { id: plan.byInput.get(plan.inputs[1]).target.name });
  return grid;
}

function renderTwoBranchTransformMerge(plan) {
  const grid = new Grid();
  const width = plan.grouped ? 4 : 3;
  place(grid, 0, 0, 'input');
  place(grid, 0, 2, 'input', plan.grouped ? { words: 2, activeWords: '0' } : {});
  place(grid, 1, 0, 'xor', { side: 'right', operator_style: 'word' });
  place(grid, 1, 1, 'free_text', {
    text: plan.alternating ? plan.texts[0] : plan.text,
    narrow: plan.alternating && !plan.grouped ? 'none' : 'left',
    portLeft: 'out', portRight: 'in', portTop: 'off', portBottom: 'off',
  });
  place(grid, 1, 2, 'split', { direction: 'top_to_left_and_bottom' });
  if (!plan.alternating) {
    place(grid, 2, 0, 'multiblockpermutation', {
      permutation: '1,0', words: String(width), activeInputs: '0,2', activeOutputs: '0,2', borders: 'invisible',
    });
    place(grid, 3, 0, 'output', plan.grouped ? { words: 2, activeWords: '0' } : {});
    place(grid, 3, 2, 'output');
    return grid;
  }
  place(grid, 2, 0, 'split', { direction: 'top_to_right_and_bottom' });
  place(grid, 2, 1, 'free_text', {
    text: plan.texts[1], narrow: plan.grouped ? 'left' : 'none',
    portLeft: 'in', portRight: 'out', portTop: 'off', portBottom: 'off',
  });
  place(grid, 2, 2, 'xor', { side: 'left', operator_style: 'word' });
  place(grid, 3, 0, 'output');
  place(grid, 3, 2, 'output', plan.grouped ? { words: 2, activeWords: '0' } : {});
  return grid;
}

function matchUnaryBinaryXor(target) {
  const xor = isCall(target.node, 'xor', 2);
  if (!xor) return null;
  for (let baseIndex = 0; baseIndex < 2; baseIndex++) {
    const base = asInput(xor.args[baseIndex]);
    const and = isCall(xor.args[1 - baseIndex], 'and', 2);
    if (!base || !and) continue;
    for (let notIndex = 0; notIndex < 2; notIndex++) {
      const not = isCall(and.args[notIndex], 'not', 1);
      const other = asInput(and.args[1 - notIndex]);
      const negated = not && asInput(not.args[0]);
      if (negated && other) return { target, base, negated, other, xor, and, not };
    }
  }
  return null;
}

function modulo(value, modulus) {
  return ((value % modulus) + modulus) % modulus;
}

function validateCyclicGroup(records) {
  const indexOf = new Map(records.map((record, index) => [record.base, index]));
  if (indexOf.size !== records.length) return null;
  const offsets = records.map((record, index) => ({
    negated: indexOf.has(record.negated) ? modulo(indexOf.get(record.negated) - index, records.length) : -1,
    other: indexOf.has(record.other) ? modulo(indexOf.get(record.other) - index, records.length) : -1,
  }));
  const first = offsets[0];
  if (first.negated <= 0 || first.other <= 0 || first.negated === first.other) return null;
  if (!offsets.every((offset) => offset.negated === first.negated && offset.other === first.other)) return null;
  return { records, negatedOffset: first.negated, otherOffset: first.other };
}

function analyzeCyclicUnaryBinaryXor(targetOrder) {
  if (targetOrder.length < 3 || targetOrder.some((target) => !target.isOutput || target.wordGroup)) return null;
  const records = targetOrder.map(matchUnaryBinaryXor);
  if (records.some((record) => !record || record.base.wordGroup)) return null;
  for (let groupSize = 3; groupSize <= records.length; groupSize++) {
    if (records.length % groupSize !== 0) continue;
    const groups = [];
    let valid = true;
    for (let start = 0; start < records.length; start += groupSize) {
      const group = validateCyclicGroup(records.slice(start, start + groupSize));
      if (!group) { valid = false; break; }
      groups.push(group);
    }
    if (valid) return { kind: 'cyclic-unary-binary-xor', groupSize, groups, outputCount: records.length };
  }
  return null;
}

function reachableCallsInAssignmentOrder(targetOrder) {
  const calls = [];
  const seen = new Set();
  const visit = (raw) => {
    const node = unwrap(raw);
    if (!node || seen.has(node) || node.kind === 'input') return;
    seen.add(node);
    if (node.kind !== 'call') return;
    node.args.forEach(visit);
    calls.push(node);
  };
  targetOrder.forEach((target) => visit(target.node));
  return calls;
}

function matchCyclicValueUpdate(raw) {
  const xor = isCall(raw, 'xor', 2);
  if (!xor) return null;
  for (let baseIndex = 0; baseIndex < 2; baseIndex++) {
    const base = unwrap(xor.args[baseIndex]);
    const and = isCall(xor.args[1 - baseIndex], 'and', 2);
    if (!base || !and) continue;
    for (let notIndex = 0; notIndex < 2; notIndex++) {
      const not = isCall(and.args[notIndex], 'not', 1);
      const negated = not && unwrap(not.args[0]);
      const other = unwrap(and.args[1 - notIndex]);
      if (negated && other) return { root: xor, base, negated, other, xor, and, not };
    }
  }
  return null;
}

function dependencyLeaves(raw, stop = new Set(), into = new Set(), seen = new Set()) {
  const node = unwrap(raw);
  if (!node || seen.has(node)) return into;
  seen.add(node);
  if (stop.has(node) || node.kind === 'input' || (node.kind === 'call' && node.args.length === 0)) {
    into.add(node);
  } else if (node.kind === 'call') {
    node.args.forEach((arg) => dependencyLeaves(arg, stop, into, seen));
  }
  return into;
}

// Plan a fixed-width register frontier without knowing its operation family.
// A call may execute when exactly one operand reaches its final use; its
// result replaces that operand's slot while the other operand remains live.
// Ready calls with non-overlapping routes share a row. Assignment discovery
// order only breaks equally valid schedules, preserving authored phase hints.
function planFrontierProgram(sources, targets, callOrder) {
  if (sources.length < targets.length || new Set(sources).size !== sources.length
      || new Set(targets).size !== targets.length) return null;
  const sourceSet = new Set(sources);
  const needed = new Set();
  const collect = (raw) => {
    const node = unwrap(raw);
    if (sourceSet.has(node)) return true;
    if (!node || node.kind !== 'call' || node.args.length < 1 || node.args.length > 2) return false;
    if (needed.has(node)) return true;
    if (!node.args.every(collect)) return false;
    needed.add(node);
    return true;
  };
  if (!targets.every(collect)) return null;
  const operations = callOrder.filter((call) => needed.has(call));
  if (operations.length !== needed.size) return null;
  const remaining = new Map();
  const addUse = (node) => remaining.set(node, (remaining.get(node) || 0) + 1);
  operations.forEach((call) => call.args.map(unwrap).forEach(addUse));
  targets.forEach(addUse);
  const slotOf = new Map(sources.map((source, index) => [source, index]));
  const activeSlots = new Set(slotOf.values());
  const pending = new Set(operations);
  const batches = [];

  while (pending.size) {
    const ready = [];
    for (const call of operations) {
      if (!pending.has(call)) continue;
      const args = call.args.map(unwrap);
      if (args.some((arg) => !slotOf.has(arg))) continue;
      if (args.length === 1) {
        if ((remaining.get(args[0]) || 0) !== 1) continue;
        const slot = slotOf.get(args[0]);
        ready.push({ call, args, arity: 1, replacementIndex: 0, replacementSlot: slot, carriedSlot: slot });
        continue;
      }
      const expiring = args.map((arg, index) => (remaining.get(arg) || 0) === 1 ? index : -1)
        .filter((index) => index >= 0);
      if (expiring.length < 1 || expiring.length > 2) continue;
      if (expiring.length === 2 && !['xor', 'and', 'or'].includes(call.typeName)) continue;
      const replacementIndex = expiring[0];
      if (replacementIndex !== 0 && !['xor', 'and', 'or'].includes(call.typeName)) continue;
      const carriedIndex = 1 - replacementIndex;
      ready.push({
        call, args, arity: 2, replacementIndex,
        replacementSlot: slotOf.get(args[replacementIndex]),
        carriedSlot: slotOf.get(args[carriedIndex]),
        carriedExpires: expiring.includes(carriedIndex),
      });
    }
    if (ready.length === 0) return null;
    // Prefer binary state updates before unary finalization. This naturally
    // delays a NOT until the old word's last binary consumer has run.
    ready.sort((a, b) => b.arity - a.arity || operations.indexOf(a.call) - operations.indexOf(b.call));
    const batch = [];
    const covered = new Set();
    for (const record of ready) {
      const lo = Math.min(record.replacementSlot, record.carriedSlot);
      const hi = Math.max(record.replacementSlot, record.carriedSlot);
      if (Array.from({ length: hi - lo + 1 }, (_, index) => lo + index).some((slot) => covered.has(slot))) continue;
      for (let slot = lo; slot <= hi; slot++) covered.add(slot);
      batch.push(record);
    }
    if (batch.length === 0) return null;
    batch.activeBefore = new Set(activeSlots);
    for (const record of batch) {
      pending.delete(record.call);
      for (const arg of record.args) remaining.set(arg, (remaining.get(arg) || 0) - 1);
      record.args.forEach((arg) => {
        if ((remaining.get(arg) || 0) === 0) slotOf.delete(arg);
      });
      if (record.carriedExpires) activeSlots.delete(record.carriedSlot);
      slotOf.set(record.call, record.replacementSlot);
    }
    batch.activeAfter = new Set(activeSlots);
    batches.push(batch);
  }
  if (targets.some((target) => !slotOf.has(target))) return null;
  const targetSlots = targets.map((target) => slotOf.get(target));
  if (new Set(targetSlots).size !== targets.length) return null;
  return { sources, targets, batches, targetSlots };
}

function analyzeParallelForkJoinSuffix(outputs) {
  const records = [];
  const seenBases = new Set();
  for (const target of outputs) {
    const root = unwrap(target.node);
    if (root?.kind !== 'call' || root.args.length !== 3) return null;
    const args = root.args.map((arg) => unwrap(arg));
    if (args[1]?.kind !== 'call') return null;
    const base = args[1];
    const branches = [0, 2].map((argIndex) => {
      const operations = [];
      let node = args[argIndex];
      while (node !== base && node?.kind === 'call' && node.args.length === 1) {
        operations.push(node);
        node = unwrap(node.args[0]);
      }
      operations.reverse();
      return node === base && operations.length > 0 ? operations : null;
    });
    if (branches.some((branch) => !branch)) return null;
    if (seenBases.has(base)) return null;
    seenBases.add(base);
    records.push({ target, root, base, left: branches[0], right: branches[1] });
  }
  return { bases: records.map((record) => record.base), records };
}

// Find a cyclic nonlinear core even when affine/in-place programs surround
// it. The core is discovered among all reachable calls, then the prefix and
// suffix are independently proven to be fixed-width frontier programs.
function analyzeWrappedCyclicStateUpdate(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  if (outputs.length < 3 || outputs.some((target) => target.wordGroup)) return null;
  const callOrder = reachableCallsInAssignmentOrder(targetOrder);
  const candidates = callOrder.map(matchCyclicValueUpdate).filter(Boolean);
  const byBase = new Map();
  for (const record of candidates) {
    if (byBase.has(record.base)) byBase.set(record.base, null);
    else byBase.set(record.base, record);
  }
  for (const start of candidates) {
    if (!byBase.get(start.base)) continue;
    const cycle = [];
    const seen = new Set();
    let value = start.base;
    while (!seen.has(value) && byBase.get(value)) {
      seen.add(value);
      const record = byBase.get(value);
      cycle.push(record);
      value = record.negated;
    }
    if (value !== start.base || cycle.length !== outputs.length) continue;
    const indexOf = new Map(cycle.map((record, index) => [record.base, index]));
    if (!cycle.every((record, index) => indexOf.get(record.negated) === (index + 1) % cycle.length
        && indexOf.get(record.other) === (index + 2) % cycle.length)) continue;

    const bases = cycle.map((record) => record.base);
    const sourceSet = new Set();
    bases.forEach((base) => dependencyLeaves(base, new Set(), sourceSet));
    const sources = [...sourceSet];
    if (sources.length < cycle.length
        || sources.some((node) => node.kind !== 'input' && !(node.kind === 'call' && node.args.length === 0))) continue;
    sources.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'input' ? -1 : 1;
      return a.kind === 'input' ? naturalNameOrder(a, b) : callOrder.indexOf(a) - callOrder.indexOf(b);
    });
    const prefix = planFrontierProgram(sources, bases, callOrder);
    if (!prefix) continue;
    const prefixFrontierSlots = [...new Set(prefix.targetSlots)].sort((a, b) => a - b);
    if (prefixFrontierSlots.length !== cycle.length) continue;
    const compactSlot = new Map(prefixFrontierSlots.map((slot, index) => [slot, index]));
    const orderedRecords = new Array(cycle.length);
    for (const record of cycle) {
      orderedRecords[compactSlot.get(prefix.targetSlots[bases.indexOf(record.base)])] = record;
    }
    if (orderedRecords.some((record) => !record)) continue;
    if (!orderedRecords.every((record, index) => orderedRecords[(index + 1) % cycle.length].base === record.negated
        && orderedRecords[(index + 2) % cycle.length].base === record.other)) continue;
    const coreRoots = orderedRecords.map((record) => record.root);
    const outputRoots = outputs.map((target) => unwrap(target.node));
    let suffix = planFrontierProgram(coreRoots, outputRoots, callOrder);
    if (!suffix) {
      const forkJoin = analyzeParallelForkJoinSuffix(outputs);
      const frontier = forkJoin && planFrontierProgram(coreRoots, forkJoin.bases, callOrder);
      if (frontier) {
        const recordByBase = new Map(forkJoin.records.map((record) => [record.base, record]));
        const records = new Array(frontier.targetSlots.length);
        forkJoin.bases.forEach((base, index) => { records[frontier.targetSlots[index]] = recordByBase.get(base); });
        if (!records.some((record) => !record)) suffix = { kind: 'frontier-fork-join', frontier, records };
      }
    }
    if (!suffix) continue;
    return {
      kind: 'wrapped-cyclic-state-update', size: cycle.length, sources, prefix,
      prefixFrontierSlots, records: orderedRecords, coreRoots, suffix, outputs, outputCount: outputs.length,
    };
  }
  return null;
}

function scalarBinaryParams(call, side) {
  const params = { ...defaultParams(call.typeName), ...call.params };
  if (['xor', 'and', 'or'].includes(call.typeName)) params.inputs = 2;
  if (BLOCK_TYPES[call.typeName]?.params.some((param) => param.name === 'side')) params.side = side;
  else {
    setComponentSidePort(params, side, 'in');
    setComponentSidePort(params, side === 'left' ? 'right' : 'left', 'off');
  }
  return params;
}

function renderFrontierProgram(grid, plan, startRow, mainColumns) {
  let row = startRow;
  for (const batch of plan.batches) {
    const occupied = new Set();
    for (const record of batch) {
      const target = mainColumns[record.replacementSlot];
      if (record.arity === 1) {
        place(grid, row, target, record.call.typeName, { ...record.call.params });
        occupied.add(target);
        continue;
      }
      const source = mainColumns[record.carriedSlot];
      const rightward = source < target;
      place(grid, row, source, record.carriedExpires ? 'wire' : 'split', {
        direction: record.carriedExpires
          ? (rightward ? 'top_to_right' : 'top_to_left')
          : (rightward ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom'),
      });
      occupied.add(source);
      for (let col = Math.min(source, target) + 1; col < Math.max(source, target); col++) {
        const vertical = mainColumns.includes(col);
        place(grid, row, col, vertical ? 'double_wire' : 'wire', vertical
          ? { variant: rightward ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left' }
          : { direction: rightward ? 'left_to_right' : 'right_to_left' });
        occupied.add(col);
      }
      place(grid, row, target, record.call.typeName,
        scalarBinaryParams(record.call, rightward ? 'left' : 'right'));
      occupied.add(target);
    }
    for (const slot of batch.activeBefore) {
      const col = mainColumns[slot];
      if (!occupied.has(col)) place(grid, row, col, 'wire');
    }
    row++;
  }
  return row;
}

function renderWrappedCyclicStateUpdate(plan) {
  const grid = new Grid();
  const mainColumns = Array.from({ length: plan.size }, (_, index) => 2 * index);
  const prefixColumns = Array.from({ length: plan.sources.length }, (_, index) => 2 * index);
  plan.sources.forEach((source, index) => place(grid, 0, prefixColumns[index],
    source.kind === 'input' ? 'input' : source.typeName,
    source.kind === 'input'
      ? { secrecy: source.secret || source.groupSecret ? 'secret' : 'public' }
      : { ...source.params }));
  let row = renderFrontierProgram(grid, plan.prefix, 1, prefixColumns);
  const prefixInputs = plan.prefixFrontierSlots.map((slot) => prefixColumns[slot]);
  if (prefixInputs.some((col, index) => col !== mainColumns[index])) {
    const params = {
      permutation: Array.from({ length: plan.size }, (_, index) => index).join(','),
      words: String(Math.max(prefixColumns.at(-1), mainColumns.at(-1)) + 1),
      activeInputs: prefixInputs.join(','), activeOutputs: mainColumns.join(','), borders: 'invisible',
    };
    place(grid, row, 0, 'multiblockpermutation', params);
    row += blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
  }
  const extra = 2 * plan.size;

  // Materialize (~x[i] & x[i+1]) beside every frontier lane. The wrap copy
  // occupies one extra column; all other copies use the gaps between lanes.
  place(grid, row, mainColumns[0], 'split', { direction: 'top_to_right_and_bottom' });
  for (let col = 1; col < extra; col++) {
    place(grid, row, col, mainColumns.includes(col) ? 'double_wire' : 'wire', mainColumns.includes(col)
      ? { variant: 'top_to_bottom+left_to_right' }
      : { direction: 'left_to_right' });
  }
  place(grid, row, extra, 'wire', { direction: 'left_to_bottom' });
  row++;

  for (let index = 0; index < plan.size; index++) {
    const main = mainColumns[index];
    place(grid, row, main, 'split', { direction: 'top_to_right_and_bottom' });
    place(grid, row, main + 1, 'wire', { direction: 'left_to_bottom' });
  }
  place(grid, row, extra, 'wire');
  row++;

  for (let index = 0; index < plan.size; index++) {
    place(grid, row, mainColumns[index], 'wire');
    place(grid, row, mainColumns[index] + 1, plan.records[index].not.typeName, { ...plan.records[index].not.params });
  }
  place(grid, row, extra, 'wire');
  row++;

  place(grid, row, mainColumns[0], 'wire');
  for (let index = 0; index < plan.size; index++) {
    const term = mainColumns[index] + 1;
    place(grid, row, term, plan.records[(index + plan.size - 1) % plan.size].and.typeName,
      scalarBinaryParams(plan.records[(index + plan.size - 1) % plan.size].and, 'right'));
    if (index + 1 < plan.size) {
      place(grid, row, mainColumns[index + 1], 'split', { direction: 'top_to_left_and_bottom' });
    }
  }
  place(grid, row, extra, 'wire', { direction: 'top_to_left' });
  row++;

  place(grid, row, mainColumns[0], 'wire');
  place(grid, row, 1, 'wire', { direction: 'top_to_right' });
  for (let col = 2; col < extra; col++) {
    place(grid, row, col, 'double_wire', { variant: 'top_to_bottom+left_to_right' });
  }
  place(grid, row, extra, 'wire', { direction: 'left_to_bottom' });
  row++;

  place(grid, row, mainColumns[0], 'wire');
  place(grid, row, 1, 'wire', { direction: 'right_to_bottom' });
  for (let col = 2; col < extra; col++) {
    if (col % 2 === 0) place(grid, row, col, 'double_wire', { variant: 'top_to_bottom+right_to_left' });
    else place(grid, row, col, 'double_wire', { variant: 'top_to_left+right_to_bottom' });
  }
  place(grid, row, extra, 'wire', { direction: 'top_to_left' });
  row++;

  for (let index = 0; index < plan.size; index++) {
    const main = mainColumns[index];
    place(grid, row, main, plan.records[index].xor.typeName,
      scalarBinaryParams(plan.records[index].xor, 'right'));
    place(grid, row, main + 1, 'wire', { direction: 'top_to_left' });
  }
  row++;

  if (plan.suffix.kind !== 'frontier-fork-join') {
    row = renderFrontierProgram(grid, plan.suffix, row, mainColumns);
    plan.outputs.forEach((target, index) => {
      place(grid, row, mainColumns[plan.suffix.targetSlots[index]], 'output', { id: target.name });
    });
    return grid;
  }
  row = renderFrontierProgram(grid, plan.suffix.frontier, row, mainColumns);

  const centers = Array.from({ length: plan.size }, (_, index) => 3 * index + 1);
  const permutationParams = {
    permutation: Array.from({ length: plan.size }, (_, index) => index).join(','),
    words: String(3 * plan.size),
    activeInputs: mainColumns.join(','),
    activeOutputs: centers.join(','),
    borders: 'invisible',
  };
  place(grid, row, 0, 'multiblockpermutation', permutationParams);
  row += blockRowSpan('multiblockpermutation', {
    ...defaultParams('multiblockpermutation'), ...permutationParams,
  });
  centers.forEach((center) => {
    place(grid, row, center, 'split', { direction: 'top_to_left_and_right_and_bottom' });
    place(grid, row, center - 1, 'wire', { direction: 'right_to_bottom' });
    place(grid, row, center + 1, 'wire', { direction: 'left_to_bottom' });
  });
  row++;
  const branchDepth = Math.max(...plan.suffix.records.flatMap((record) => [record.left.length, record.right.length]));
  for (let depth = 0; depth < branchDepth; depth++) {
    plan.suffix.records.forEach((record, index) => {
      const center = centers[index];
      const left = record.left[depth];
      const right = record.right[depth];
      place(grid, row, center - 1, left?.typeName ?? 'wire', left ? { ...left.params } : {});
      place(grid, row, center, 'wire');
      place(grid, row, center + 1, right?.typeName ?? 'wire', right ? { ...right.params } : {});
    });
    row++;
  }
  plan.suffix.records.forEach((record, index) => {
    const center = centers[index];
    place(grid, row, center - 1, 'wire', { direction: 'top_to_right' });
    place(grid, row, center, record.root.typeName, { ...record.root.params, inputs: 3 });
    place(grid, row, center + 1, 'wire', { direction: 'top_to_left' });
  });
  row++;
  plan.suffix.records.forEach((record, index) => place(grid, row, centers[index], 'output', { id: record.target.name }));
  return grid;
}

// Atomic semantic selection. Composition below invokes this same list for
// each dependency-separated region, so a whole graph and each of its stages
// are judged by identical primitive-agnostic rules.
function analyzeAtomicSemanticGraph(targetOrder) {
  const parity = analyzeCyclicColumnParity(targetOrder);
  if (parity) return parity;
  const rotatedParity = analyzeRotatedParityRing(targetOrder);
  if (rotatedParity) return rotatedParity;
  const forkJoin = analyzeParallelForkJoin(targetOrder);
  if (forkJoin) return forkJoin;
  const serialWideTransforms = analyzeSerialWideTransforms(targetOrder);
  if (serialWideTransforms) return serialWideTransforms;
  const parallelGroupedPipeline = analyzeParallelGroupedPipeline(targetOrder);
  if (parallelGroupedPipeline) return parallelGroupedPipeline;
  const parallelWideDoubleRound = analyzeParallelWideDoubleRound(targetOrder);
  if (parallelWideDoubleRound) return parallelWideDoubleRound;
  const twoBranchTransformMerge = analyzeTwoBranchTransformMerge(targetOrder);
  if (twoBranchTransformMerge) return twoBranchTransformMerge;
  const sharedMiddleFork = analyzeSharedMiddleFork(targetOrder);
  if (sharedMiddleFork) return sharedMiddleFork;
  const unary = analyzeParallelUnaryChains(targetOrder);
  if (unary) return unary;
  const permutation = analyzePurePermutation(targetOrder);
  if (permutation) return permutation;
  const wrappedCyclic = analyzeWrappedCyclicStateUpdate(targetOrder);
  if (wrappedCyclic) return wrappedCyclic;
  const cyclic = analyzeCyclicUnaryBinaryXor(targetOrder);
  if (cyclic) return cyclic;
  const layeredStateUpdates = analyzeLayeredStateUpdates(targetOrder);
  if (layeredStateUpdates) return layeredStateUpdates;
  const tupleFrontierRounds = analyzeTupleFrontierRounds(targetOrder);
  if (tupleFrontierRounds) return tupleFrontierRounds;
  const tupleLanePipeline = analyzeTupleLanePipeline(targetOrder);
  if (tupleLanePipeline) return tupleLanePipeline;
  const forkedReduction = analyzeForkedReduction(targetOrder);
  if (forkedReduction) return forkedReduction;
  const independentComponents = analyzeIndependentComponents(targetOrder);
  if (independentComponents) return independentComponents;
  return null;
}

function frontierDependsOn(raw, candidates, seen = new Set()) {
  const node = unwrap(raw);
  if (!node || seen.has(node)) return false;
  seen.add(node);
  if (candidates.has(node)) return true;
  return node.kind === 'call' && node.args.some((arg) => frontierDependsOn(arg, candidates, seen));
}

function semanticPhysicalInputs(plan) {
  if (plan.kind === 'rotated-parity-ring') return plan.inputs;
  if (plan.kind === 'parallel-unary-chains' || plan.kind === 'pure-permutation') return plan.inputs;
  if (plan.kind === 'cyclic-unary-binary-xor') return plan.groups.flatMap((group) => group.records.map((record) => record.base));
  if (plan.kind === 'independent-components' && plan.components.every((component) => component.length === 1)) {
    return plan.components.flatMap((component) => [...reachableInputs(component[0].node)].sort(naturalNameOrder));
  }
  return null;
}

function semanticPhysicalOutputs(plan) {
  if (plan.kind === 'rotated-parity-ring') return plan.physicalOutputs;
  if (plan.kind === 'parallel-unary-chains' || plan.kind === 'pure-permutation') return plan.records.map((record) => record.target);
  if (plan.kind === 'cyclic-unary-binary-xor') return plan.groups.flatMap((group) => group.records.map((record) => record.target));
  if (plan.kind === 'independent-components' && plan.components.every((component) => component.length === 1)) {
    return plan.components.flat();
  }
  return null;
}

function stageBetweenFrontiers(previous, next) {
  const previousSet = new Set(previous.roots);
  const reached = new Set();
  for (const root of next.roots) {
    const leaves = dependencyLeaves(root, previousSet);
    for (const leaf of leaves) {
      if (previousSet.has(leaf)) reached.add(leaf);
      else if (!(leaf.kind === 'call' && leaf.args.length === 0)) return null;
    }
  }
  if (reached.size !== previous.roots.length) return null;

  const replacements = new Map(previous.roots.map((root, index) => [root, {
    kind: 'input', name: `input[${index + 1}]`,
    secret: Boolean(root.secret), groupSecret: Boolean(root.groupSecret), wordGroup: null,
  }]));
  const memo = new Map();
  const clone = (raw) => {
    const node = unwrap(raw);
    if (replacements.has(node)) return replacements.get(node);
    if (memo.has(node)) return memo.get(node);
    if (!node || node.kind === 'input') return null;
    let copy;
    if (node.kind === 'call') {
      const args = node.args.map(clone);
      if (args.some((arg) => !arg)) return null;
      copy = { ...node, params: { ...node.params }, args };
    } else if (node.kind === 'index') {
      const of = clone(node.of);
      if (!of) return null;
      copy = { ...node, of };
    } else return null;
    memo.set(node, copy);
    return copy;
  };
  const stageTargets = next.roots.map((root, index) => ({
    name: `output[${index + 1}]`, isOutput: true, node: clone(root),
    wordGroup: next.targets?.[index]?.wordGroup ?? null,
  }));
  if (stageTargets.some((target) => !target.node)) return null;
  try {
    const plan = analyzeAtomicSemanticGraph(stageTargets);
    if (plan) {
      const physicalInputs = semanticPhysicalInputs(plan);
      const physicalOutputs = semanticPhysicalOutputs(plan);
      if (!physicalInputs || !physicalOutputs) return null;
      const inputOrder = physicalInputs.map((node) => [...replacements.values()].indexOf(node));
      const outputOrder = physicalOutputs.map((target) => stageTargets
        .findIndex((candidate) => unwrap(candidate.node) === unwrap(target.node)));
      if (inputOrder.length !== previous.roots.length || outputOrder.length !== next.roots.length
          || inputOrder.some((index) => index < 0) || outputOrder.some((index) => index < 0)) return null;
      return { plan, grid: renderSemanticPlan(plan), semantic: true, inputOrder, outputOrder };
    }
    const grid = graphToGridDirectBus(stageTargets);
    // Direct routing is useful for a small glue phase, but must not turn the
    // composition search into a disguised whole-graph fallback.
    if (grid.dimensions().rows > 6) return null;
    const identity = Array.from({ length: previous.roots.length }, (_, index) => index);
    return { plan: null, grid, semantic: false, inputOrder: identity, outputOrder: identity };
  } catch {
    return null;
  }
}

function analyzeComposedStages(targetOrder) {
  const outputs = targetOrder.filter((target) => target.isOutput).sort(naturalNameOrder);
  const width = outputs.length;
  if (width < 3) return null;
  const outputRoots = outputs.map((target) => unwrap(target.node));
  const initialRoots = [...outputRoots.reduce((set, root) => reachableInputs(root, set), new Set())]
    .sort(naturalNameOrder);
  if (initialRoots.length !== width) return null;

  const intermediates = targetOrder.filter((target) => !target.isOutput);
  const candidates = [{ roots: initialRoots, targets: null, start: -1, end: -1 }];
  const seen = new Set();
  for (let start = 0; start + width <= intermediates.length; start++) {
    const targets = intermediates.slice(start, start + width);
    const roots = targets.map((target) => unwrap(target.node));
    if (new Set(roots).size !== width) continue;
    const rootSet = new Set(roots);
    if (roots.some((root) => frontierDependsOn(root, new Set([...rootSet].filter((candidate) => candidate !== root))))) continue;
    const key = roots.map((root) => targetOrder.findIndex((target) => unwrap(target.node) === root)).join(',');
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push({ roots, targets, start, end: start + width - 1 });
  }
  candidates.push({ roots: outputRoots, targets: outputs, start: Number.POSITIVE_INFINITY, end: Number.POSITIVE_INFINITY });

  const best = new Array(candidates.length).fill(null);
  best[0] = { score: 0, semanticStages: 0, stages: [] };
  for (let nextIndex = 1; nextIndex < candidates.length; nextIndex++) {
    for (let previousIndex = 0; previousIndex < nextIndex; previousIndex++) {
      const prefix = best[previousIndex];
      if (!prefix || candidates[previousIndex].end >= candidates[nextIndex].start) continue;
      const stage = stageBetweenFrontiers(candidates[previousIndex], candidates[nextIndex]);
      if (!stage) continue;
      const metrics = semanticLayoutMetrics(stage.grid);
      const candidate = {
        score: prefix.score + qualityScore(metrics) + (stage.semantic ? 0 : 200),
        semanticStages: prefix.semanticStages + (stage.semantic ? 1 : 0),
        stages: [...prefix.stages, stage],
      };
      const current = best[nextIndex];
      if (!current || candidate.score < current.score) best[nextIndex] = candidate;
    }
  }
  const result = best.at(-1);
  if (!result || result.stages.length < 2 || result.semanticStages < 2) return null;
  const identity = Array.from({ length: width }, (_, index) => index);
  if (result.stages[0].inputOrder.some((value, index) => value !== identity[index])
      || result.stages.at(-1).outputOrder.some((value, index) => value !== identity[index])) return null;
  return { kind: 'composed-stages', stages: result.stages, outputCount: width };
}

// Generic semantic selection. Every active rule is parameterized by graph
// structure (fan-out, cyclic offsets, repeated isomorphism, tuple width and
// dependency order). No primitive name, round constant, rotation table or
// whole-primitive operation count participates in selection.
export function analyzeSemanticGraph(targetOrder) {
  return analyzeAtomicSemanticGraph(targetOrder) || analyzeComposedStages(targetOrder);
}

function place(grid, row, col, type, params = {}) {
  return grid.placeBlock(row, col, type, { ...defaultParams(type), ...params });
}

function placeParallelBranches(grid, row, vertical, routes, componentType) {
  const covered = new Set();
  for (const { source, target } of routes) {
    const lo = Math.min(source, target);
    const hi = Math.max(source, target);
    for (let col = lo; col <= hi; col++) {
      if (covered.has(col)) throw new Error(`Overlapping semantic routes at column ${col}.`);
      covered.add(col);
    }
  }

  for (const col of [...vertical].sort((a, b) => a - b)) {
    if (!covered.has(col)) place(grid, row, col, 'wire');
  }

  for (const route of routes) {
    const { source, target, record } = route;
    const leftToRight = source < target;
    const lo = Math.min(source, target);
    const hi = Math.max(source, target);
    place(grid, row, source, 'split', {
      direction: leftToRight ? 'top_to_right_and_bottom' : 'top_to_left_and_bottom',
    });
    for (let col = lo + 1; col < hi; col++) {
      if (vertical.has(col)) {
        place(grid, row, col, 'double_wire', {
          variant: leftToRight ? 'top_to_bottom+left_to_right' : 'top_to_bottom+right_to_left',
        });
      } else {
        place(grid, row, col, 'wire', { direction: leftToRight ? 'left_to_right' : 'right_to_left' });
      }
    }
    if (componentType === 'not') {
      place(grid, row, target, 'not', {
        ...record.not.params,
        inputs: 1,
        operator_style: record.not.params.operator_style ?? 'symbol',
        portTop: 'off',
        portLeft: leftToRight ? 'in' : 'off',
        portRight: leftToRight ? 'off' : 'in',
        portBottom: 'out',
      });
      vertical.add(target);
    } else {
      place(grid, row, target, 'and', {
        ...record.and.params,
        inputs: 2,
        side: leftToRight ? 'left' : 'right',
        operator_style: record.and.params.operator_style ?? 'symbol',
      });
    }
  }
  return row + 1;
}

function renderInterleavedCyclic(plan) {
  const grid = new Grid();
  const laneColumn = (group, index) => 2 * (group * plan.groupSize + index);
  const termColumn = (group, index) => laneColumn(group, index) + 1;
  const stateColumns = [];

  for (let group = 0; group < plan.groups.length; group++) {
    for (let index = 0; index < plan.groupSize; index++) {
      const record = plan.groups[group].records[index];
      const col = laneColumn(group, index);
      stateColumns.push(col);
      place(grid, 0, col, 'input', { secrecy: record.base.secret || record.base.groupSecret ? 'secret' : 'public' });
    }
  }

  const vertical = new Set(stateColumns);
  let row = 1;
  for (let index = 0; index < plan.groupSize; index++) {
    const notRoutes = [];
    const andRoutes = [];
    for (let group = 0; group < plan.groups.length; group++) {
      const cyclic = plan.groups[group];
      const record = cyclic.records[index];
      notRoutes.push({
        source: laneColumn(group, modulo(index + cyclic.negatedOffset, plan.groupSize)),
        target: termColumn(group, index),
        record,
      });
      andRoutes.push({
        source: laneColumn(group, modulo(index + cyclic.otherOffset, plan.groupSize)),
        target: termColumn(group, index),
        record,
      });
    }
    row = placeParallelBranches(grid, row, vertical, notRoutes, 'not');
    row = placeParallelBranches(grid, row, vertical, andRoutes, 'and');
  }

  for (let group = 0; group < plan.groups.length; group++) {
    for (let index = 0; index < plan.groupSize; index++) {
      const record = plan.groups[group].records[index];
      const state = laneColumn(group, index);
      const term = termColumn(group, index);
      place(grid, row, state, 'xor', {
        ...record.xor.params,
        inputs: 2,
        side: 'right',
        operator_style: record.xor.params.operator_style ?? 'symbol',
      });
      place(grid, row, term, 'wire', { direction: 'top_to_left' });
      vertical.delete(term);
    }
  }
  row++;
  for (const col of stateColumns) place(grid, row, col, 'output');
  return grid;
}

const VERTICAL_SIDES = new Set(['top', 'bottom']);
const HORIZONTAL_SIDES = new Set(['left', 'right']);

function isStraight(a, b) {
  if (VERTICAL_SIDES.has(a.side) && VERTICAL_SIDES.has(b.side)) return a.side !== b.side && a.wordOffset === b.wordOffset;
  if (HORIZONTAL_SIDES.has(a.side) && HORIZONTAL_SIDES.has(b.side)) return a.side !== b.side;
  return false;
}

export function semanticLayoutMetrics(grid) {
  const { rows, cols } = grid.dimensions();
  let turns = 0;
  let crossings = 0;
  const blocks = grid.allBlocks().filter((block) => !block.raw);
  for (const block of blocks) {
    if (block.type === 'double_wire') crossings++;
    const { routes } = blockRoutes(block.type, block.params);
    for (const route of routes) {
      for (const into of route.into) for (const out of route.outs) if (!isStraight(into, out)) turns++;
    }
  }
  return { rows, cols, blocks: blocks.length, turns, crossings };
}

function qualityScore(metrics) {
  return 20 * metrics.crossings + 8 * metrics.turns + 3 * metrics.rows + 2 * metrics.cols + metrics.blocks;
}

function ioWordColumns(grid, type) {
  return grid.allBlocks()
    .filter((block) => block.type === type)
    .flatMap((block) => {
      const words = blockWords(type, block.params);
      return resolveActiveWords(block.params, words).map((word) => block.col + word);
    })
    .sort((a, b) => a - b);
}

function renderComposedStages(plan) {
  const grid = new Grid();
  const stages = plan.stages.map((stage) => stage.grid);
  let offset = 0;
  const first = stages[0];
  grid.placeBatch(first.allBlocks().filter((block) => block.type !== 'output'), 0, 0);

  for (let index = 1; index < stages.length; index++) {
    const previous = stages[index - 1];
    const next = stages[index];
    const previousOutputRow = Math.min(...previous.allBlocks().filter((block) => block.type === 'output').map((block) => block.row));
    const transitionRow = offset + previousOutputRow;
    const inputs = ioWordColumns(previous, 'output');
    const outputs = ioWordColumns(next, 'input');
    if (inputs.length !== outputs.length) throw new Error('Composed stages disagree on frontier width.');
    const destination = new Map(plan.stages[index].inputOrder.map((logical, physical) => [logical, physical]));
    const permutation = plan.stages[index - 1].outputOrder.map((logical) => destination.get(logical));
    if (permutation.some((value) => value === undefined)) throw new Error('Composed stages lost a logical frontier lane.');
    let span = 1;
    if (permutation.every((destinationIndex, sourceIndex) => destinationIndex === sourceIndex)
        && inputs.every((col, word) => col === outputs[word])) {
      inputs.forEach((col) => place(grid, transitionRow, col, 'wire'));
    } else {
      const params = {
        permutation: permutation.join(','),
        words: String(Math.max(...inputs, ...outputs) + 1),
        activeInputs: inputs.join(','), activeOutputs: outputs.join(','), borders: 'invisible',
      };
      place(grid, transitionRow, 0, 'multiblockpermutation', params);
      span = blockRowSpan('multiblockpermutation', { ...defaultParams('multiblockpermutation'), ...params });
    }
    offset = transitionRow + span - 1;
    const last = index === stages.length - 1;
    grid.placeBatch(next.allBlocks().filter((block) => block.type !== 'input' && (last || block.type !== 'output')), offset, 0);
  }
  return grid;
}

function renderSemanticPlan(plan) {
  const renderers = {
    'pure-permutation': renderPurePermutation,
    'parallel-unary-chains': renderParallelUnaryChains,
    'cyclic-column-parity': renderCyclicColumnParity,
    'rotated-parity-ring': renderRotatedParityRing,
    'parallel-fork-join': renderParallelForkJoin,
    'serial-wide-transforms': renderSerialWideTransforms,
    'parallel-grouped-pipeline': renderParallelGroupedPipeline,
    'parallel-wide-double-round': renderParallelWideDoubleRound,
    'two-branch-transform-merge': renderTwoBranchTransformMerge,
    'shared-middle-fork': renderSharedMiddleFork,
    'wrapped-cyclic-state-update': renderWrappedCyclicStateUpdate,
    'cyclic-unary-binary-xor': renderInterleavedCyclic,
    'layered-state-updates': renderLayeredStateUpdates,
    'tuple-frontier-rounds': renderTupleFrontierRounds,
    'tuple-lane-pipeline': renderTupleLanePipeline,
    'forked-reduction': renderForkedReduction,
    'independent-components': renderIndependentComponents,
    'composed-stages': renderComposedStages,
  };
  const renderer = renderers[plan.kind];
  if (!renderer) throw new Error(`No renderer for generic semantic pattern ${plan.kind}.`);
  return renderer(plan);
}

export function buildSemanticLayoutCandidates(targetOrder) {
  const plan = analyzeSemanticGraph(targetOrder);
  if (!plan) return { plan: null, candidates: [] };
  const candidateNames = {
    'pure-permutation': 'multiblock-permutation',
    'cyclic-unary-binary-xor': 'interleaved-cyclic-stencil',
  };
  const grid = renderSemanticPlan(plan);
  const candidates = [{ name: candidateNames[plan.kind] ?? plan.kind, grid }];
  for (const candidate of candidates) {
    const connectivity = checkConnectivity(candidate.grid);
    if (!connectivity.wellConnected) {
      const first = connectivity.problems[0];
      throw new Error(`Semantic layout produced an invalid diagram (${first.message}).`);
    }
    candidate.metrics = semanticLayoutMetrics(candidate.grid);
    candidate.score = qualityScore(candidate.metrics);
  }
  candidates.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));
  return { plan, candidates };
}
