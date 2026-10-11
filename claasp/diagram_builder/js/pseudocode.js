// Bidirectional compiler between a Grid (see grid.js) and "pseudocode": a
// small variable/function-call notation that drops wiring entirely and
// shows only the actual dataflow, e.g.:
//   output = xor(rotate[amount=19](input1), input2, rotate[amount=28](input3))
//
// gridToPseudocode (extraction) traces every port's value through the grid
// -- eliminating wire/split/swap/double_wire/multiblockpermutation, which
// route values but never compute anything -- and emits one assignment per
// output/intermediate_output word.
//
// pseudocodeToGrid (synthesis) parses that notation into an expression DAG
// (parseAssignments/buildGraph). semantic-auto first offers that DAG to the
// integrated human-drawing engine: semanticLayout.js preserves recognized
// repeated circuit families, and its slot router handles compact supported
// graphs. Explicitly unsupported shapes go first to a readable direct-bus
// synthesizer, then to the collision-free conservative bus as a totality
// backstop; only shapes that require still more specialized handling fall
// through to pseudocodeLayout.js/ELK. The layout
// this produces is not intended to match a hand-drawn diagram byte-for-
// byte (that's not a well-defined target for an arbitrary DAG) -- only to
// be a *correct*, valid grid whose own dataflow is exactly what the
// pseudocode says.
import { operandOrder, BLOCK_TYPES, blockPorts, blockRowSpan, defaultParams, resolveActiveWords } from './blockCatalog.js';
import { blockRoutes } from './render.js';
import { OPPOSITE_SIDE, NEIGHBOR_OFFSET, localWordIndex, checkConnectivity } from './connectivity.js';
import { buildElkGraph, layoutToGrid, alignDeclaredOutputs } from './pseudocodeLayout.js';
import { graphToGridHumanDrawing } from './layout/strategies/human-drawing/synth.js';
import { graphToGridDirectBus } from './layout/strategies/direct-bus.js';
import { graphToGridConservative } from './layout/strategies/conservative-bus.js';
import { renderGrid } from './render.js';
import { decodeGrid } from './decode.js';

// ---------------------------------------------------------- grid -> code --

// Which of a component's own params are part of its actual *operation*
// (kept in pseudocode) as opposed to purely visual/style choices (dropped):
// operator_style, free_text(the override text), label, borders, surjective,
// narrow, secrecy, merged, activeWords, side, and every port override are
// all style/structural -- side is implied by argument position, and
// `inputs`/`words` are implied by the argument count. free_text is handled
// separately (its `text` becomes the function name itself, not a param).
export const OPERATOR_PARAM_NAMES = {
  rotate: ['direction', 'amount'],
  shift: ['direction', 'amount'],
  variablerotate: ['direction'],
  variableshift: ['direction'],
  constant: ['value'],
};

function operatorParams(typeName, params) {
  const names = OPERATOR_PARAM_NAMES[typeName] || [];
  const defaults = defaultParams(typeName);
  const result = {};
  for (const name of names) {
    if (params[name] !== undefined && params[name] !== defaults[name]) result[name] = params[name];
  }
  return result;
}

function fnName(typeName, params) {
  return ['free_text','typedbox'].includes(typeName) ? params.text || typeName : typeName;
}

function portKey(row, col, side, word) {
  return `${row},${col}|${side}|${word}`;
}

// Reading order for both input-naming and output/intermediate-naming: top
// to bottom, then left to right -- matches how a person reads the diagram,
// and (for outputs) guarantees an earlier-named value is always available
// by the time a later expression might reuse it (see NAMED_FOR below).
function byReadingOrder(a, b) {
  return a.row - b.row || a.col - b.col;
}

// Assigns names to every active word across a set of same-role blocks
// (all `input`, or all `output`/`intermediate_output`): a block with a
// customized label gets its own bare-or-indexed name; every default-
// labeled block shares one pool (named `fallbackBase`, e.g. "input" or
// "output"), indexed together in reading order. A pool with exactly one
// word uses the bare name; more than one gets [1], [2], ... suffixes.
function assignNames(entries, fallbackBase) {
  const pools = new Map(); // baseName -> [{row,col,word}]
  for (const e of entries) {
    if (!pools.has(e.base)) pools.set(e.base, []);
    pools.get(e.base).push(e);
  }
  const names = new Map(); // "row,col,word" -> name
  for (const [base, list] of pools) {
    list.sort(byReadingOrder2);
    const bare = base || fallbackBase;
    list.forEach((e, i) => {
      names.set(`${e.row},${e.col},${e.word}`, list.length === 1 ? bare : `${bare}[${i + 1}]`);
    });
  }
  return names;
}
function byReadingOrder2(a, b) {
  return a.row - b.row || a.col - b.col || a.word - b.word;
}

function labelBase(block) {
  const label = block.params.label;
  return label && label !== 'round' ? label : '';
}

export function gridToPseudocode(grid, { diagnostics } = {}) {
  const blocks = grid.allBlocks().filter((b) => !b.raw);

  // ---- name every input word --------------------------------------------
  const inputEntries = [];
  for (const b of blocks) {
    if (!(BLOCK_TYPES[b.type].family === 'io' && BLOCK_TYPES[b.type].kind === 'input')) continue;
    const active = resolveActiveWords(b.params, b.words);
    for (const w of active) inputEntries.push({ row: b.row, col: b.col + w, word: 0, base: '', block: b });
  }
  const inputNames = assignNames(inputEntries, 'input');
  const explicitInputNames = new Set();
  for (const entry of inputEntries) {
    const index = entry.block.params.source_index;
    if (!index) continue;
    if (entry.block.words !== 1 || !/^[1-9]\d{0,5}$/.test(String(index))) throw new Error('Invalid visible input index');
    const name = `input[${index}]`;
    if (explicitInputNames.has(name)) throw new Error(`Duplicate visible input identity ${name}`);
    explicitInputNames.add(name);
    inputNames.set(`${entry.row},${entry.col},${entry.word}`,name);
  }
  const allInputNames=[...inputNames.values()];
  if (new Set(allInputNames).size!==allInputNames.length) throw new Error('Explicit and positional input identities conflict');

  // ---- declarations preamble: secrecy + multi-word grouping, per input
  // block -- both are dropped by every other part of this extraction
  // (see OPERATOR_PARAM_NAMES's own comment), so they're recovered here as
  // a small header `pseudocodeToGrid` reads back (see parseDeclarations).
  // A block's own active-word entries are always contiguous in reading
  // order (blocks never interleave column ranges within a row), so a
  // single pass re-grouping the same, already-sorted entries by block is
  // enough -- no extra bookkeeping needed to find each block's run.
  const declLines = [];
  const sortedInputEntries = [...inputEntries].sort(byReadingOrder2);
  for (let i = 0; i < sortedInputEntries.length; ) {
    const b = sortedInputEntries[i].block;
    let j = i;
    while (j < sortedInputEntries.length && sortedInputEntries[j].block === b) j++;
    const runNames = [];
    for (let k = i; k < j; k++) {
      const e = sortedInputEntries[k];
      runNames.push(inputNames.get(`${e.row},${e.col},${e.word}`));
    }
    if (b.words > 1 && runNames.length > 0) declLines.push(`words ${runNames.join(', ')} = ${b.words}`);
    if (b.params.secrecy === 'secret') for (const n of runNames) declLines.push(`secret ${n}`);
    i = j;
  }

  // ---- name every output/intermediate_output word (per its own base) ----
  const outEntries = [];
  const interEntries = [];
  for (const b of blocks) {
    const type = BLOCK_TYPES[b.type];
    if (type.family !== 'io' || (type.kind !== 'output' && type.kind !== 'intermediate_output')) continue;
    const active = resolveActiveWords(b.params, b.words);
    const list = type.kind === 'output' ? outEntries : interEntries;
    for (const w of active) list.push({ row: b.row, col: b.col + w, word: 0, base: labelBase(b), block: b });
  }
  const outputNames = assignNames(outEntries, 'output');
  // A synthesized scalar output carries its original assignment name as
  // hidden semantic metadata. Preserve it even when state-lane alignment
  // places output[2] physically to the left of output[1]. The id remains a
  // short, human-facing label (OUT0, OUT1, ...).
  for (const entry of outEntries) {
    const explicit = entry.block.words === 1
      ? (entry.block.params.semanticName || entry.block.params.id)
      : '';
    if (/^output(?:\[\d+\])?$/.test(explicit)) {
      outputNames.set(`${entry.row},${entry.col},${entry.word}`, explicit);
    }
  }
  const interNames = assignNames(interEntries, 'temp');

  // A multi-word `output` block (not intermediate_output -- a tapped
  // intermediate is already routable as a single 'named' graph node
  // regardless of width, see buildGraph's own comment on that shape) has
  // the identical word-size-loss gap as a multi-word input: each active
  // word becomes its own independently-numbered pseudocode name, with
  // nothing linking them back into one physical block. Same declaration,
  // same re-grouping-by-block pass as the input one above -- EXCEPT an
  // output (unlike an input) also has its own `merged` param: `words>1`
  // with `merged:false` means "N separate, individually-boxed outputs
  // that happen to share one Block record" (confirmed directly: every
  // classical/type1-5/alternating Feistel construction's own two half-
  // outputs are exactly this shape, `words:2, merged:false`), which is
  // NOT "one physically wide block" at all -- only `merged !== false`
  // (the default, true) is the shape this declaration is for. Missing
  // this distinction was a real, corpus-wide regression (28 previously-
  // working files, every one of them a `merged:false` two-output
  // construction) caught by re-running the full corpus, not by reasoning
  // alone -- confirming yet again why that verification step is not
  // optional in this file's own area.
  const sortedOutEntries = [...outEntries].sort(byReadingOrder2);
  for (let i = 0; i < sortedOutEntries.length; ) {
    const b = sortedOutEntries[i].block;
    let j = i;
    while (j < sortedOutEntries.length && sortedOutEntries[j].block === b) j++;
    if (b.words > 1 && b.params.merged !== false) {
      const runNames = [];
      for (let k = i; k < j; k++) {
        const e = sortedOutEntries[k];
        runNames.push(outputNames.get(`${e.row},${e.col},${e.word}`));
      }
      if (runNames.length > 0) declLines.push(`words ${runNames.join(', ')} = ${b.words}`);
    }
    i = j;
  }

  // ---- fixed-point trace of every port's expression ----------------------
  const portValue = new Map(); // portKey -> ExprNode
  const wireWatchers = new Map();
  const pendingPorts=[];
  let drainingPorts=false;
  const setPortValue = (key,value) => {
    if(portValue.has(key))return;
    portValue.set(key,value);pendingPorts.push(key);
    if(drainingPorts)return;
    drainingPorts=true;
    while(pendingPorts.length) {
      const source=pendingPorts.pop(),sourceValue=portValue.get(source);
      const target=adjacentOutput.get(source);
      if(target&&!portValue.has(target)){portValue.set(target,sourceValue);pendingPorts.push(target);}
      for(const route of wireWatchers.get(source)||[]) {
        if(!route.inputs.length||!route.inputs.every(k=>portValue.has(k)))continue;
        const routed=portValue.get(route.inputs[0]);
        for(const output of route.outputs)if(!portValue.has(output)){portValue.set(output,routed);pendingPorts.push(output);}
      }
    }
    drainingPorts=false;
  };
  const adjacentOutput = new Map();
  const wiringRoutes = new Map();
  const scalarPorts = new Map();
  for (const b of blocks) {
    const family=BLOCK_TYPES[b.type].family;
    if (['wiring','double_wire','swap','multiblockpermutation'].includes(family)) {
      wiringRoutes.set(b,blockRoutes(b.type,b.params).routes.map(route=>({
        inputs:route.into.map(p=>portKey(b.row,b.col,p.side,p.wordOffset)),
        outputs:route.outs.map(p=>portKey(b.row,b.col,p.side,p.wordOffset))
      })));
    } else if(family==='component'&&b.words===1)scalarPorts.set(b,blockPorts(b.type,b.params,0,1));
  }
  for (const b of blocks) for (let w = 0; w < b.words; w++) {
    const col = b.col + w;
    const ports = blockPorts(b.type, b.params, w, b.words);
    for (const side of ['top', 'left', 'right', 'bottom']) {
      if (ports[side] !== 'out') continue;
      const [dRow, dCol] = NEIGHBOR_OFFSET[side];
      const neighborRow = side === 'bottom' ? b.row + b.rowSpan : b.row + dRow;
      const neighbor = grid.getBlockAt(neighborRow, col + dCol);
      if (!neighbor || neighbor.raw) continue;
      const facingSide = OPPOSITE_SIDE[side];
      const neighborWordIndex = localWordIndex(neighbor, facingSide, neighborRow, col + dCol);
      adjacentOutput.set(portKey(b.row,b.col,side,w), portKey(neighbor.row,neighbor.col,facingSide,neighborWordIndex));
    }
  }
  for(const routes of wiringRoutes.values())for(const route of routes)for(const input of route.inputs) {
    if(!wireWatchers.has(input))wireWatchers.set(input,[]);wireWatchers.get(input).push(route);
  }
  for (const b of blocks) {
    if (!(BLOCK_TYPES[b.type].family === 'io' && BLOCK_TYPES[b.type].kind === 'input')) continue;
    const active = resolveActiveWords(b.params, b.words);
    for (const w of active) {
      const name = inputNames.get(`${b.row},${b.col + w},0`);
      setPortValue(portKey(b.row, b.col, 'bottom', w), { kind: 'var', name });
    }
  }

  const assignments = []; // { name, exprNode } in emission order
  const namedFor = new Map(); // ExprNode -> name (for CSE when a fan-out value is also a named output)
  const emitted = new Set(); // "row,col,word" already turned into an assignment
  const computedComponents = new Set();

  let changed = true;
  let iterations = 0;
  while (changed && iterations <= blocks.length) {
    changed = false;
    iterations++;
    for (const b of blocks) {
      const type = BLOCK_TYPES[b.type];

      if (type.family === 'io' && type.kind === 'input') continue;

      if (type.family === 'io' && (type.kind === 'output' || type.kind === 'intermediate_output')) {
        const active = resolveActiveWords(b.params, b.words);
        for (const w of active) {
          const key = `${b.row},${b.col + w},0`;
          if (emitted.has(key)) continue;
          const inKey = portKey(b.row, b.col, 'top', w);
          if (!portValue.has(inKey)) continue;
          const expr = portValue.get(inKey);
          const name = type.kind === 'output' ? outputNames.get(key) : interNames.get(key);
          // A value node that's already the root of an earlier assignment
          // (a split feeding two output words the same computed value) is
          // referenced by that name instead of re-inlined -- renderExpr
          // would otherwise duplicate the whole subtree on both lines, and
          // resynthesis would then build two separate copies of it. Plain
          // var exprs are left alone (already atomic, nothing duplicated);
          // namedFor keeps the FIRST name so every later reference agrees.
          const alias = expr.kind !== 'var' && namedFor.has(expr) ? { kind: 'var', name: namedFor.get(expr) } : null;
          assignments.push({ name, expr: alias || expr, row: b.row, col: b.col + w });
          emitted.add(key);
          if (!namedFor.has(expr)) namedFor.set(expr, name);
          if (type.kind === 'intermediate_output') {
            setPortValue(portKey(b.row, b.col, 'bottom', w), { kind: 'var', name });
          }
          changed = true;
        }
        continue;
      }

      if (type.family === 'component') {
        const multiWord = b.words > 1;
        if (multiWord) {
          // A multi-word component (mixcolumn, a >1-word rotate/shift, ...)
          // computes ONE function of every word's own top-in *together*
          // (see blockCatalog.js: multi-word inputs=1 gives each word its
          // own top port, but that's still one signal, e.g. MixColumn's
          // whole 4-byte column) and produces one *tuple* result, not an
          // independent per-word value -- 'index' below is how a later
          // consumer reaches word i of that result, matching this file's
          // own generated pseudocode.js reverse direction, which parses
          // exactly that shape back in.
          // Output word zero may be inactive. Using its port as a completion
          // sentinel rebuilt such components on every pass until the 2000
          // iteration limit, even after all active outputs were resolved.
          if (!computedComponents.has(b)) {
            // Only words that actually HAVE a top in-port (a partial
            // activeInputs leaves spacer words with no port at all -- see
            // blockCatalog.js's blockPorts) can ever receive a value;
            // demanding every word 0..words-1 here made any partial
            // multi-word component stall the whole fixed point silently
            // (confirmed live: gimli[rounds=3]_compact's 15-word SP-box
            // with spacer columns 3/7/11 extracted to empty pseudocode).
            const inWords = Array.from({ length: b.words }, (_, w) => w).filter(
              (w) => blockPorts(b.type, b.params, w, b.words).top === 'in'
            );
            const needed = inWords.map((w) => portKey(b.row, b.col, 'top', w));
            if (needed.every((k) => portValue.has(k))) {
              const args = needed.map((k) => portValue.get(k));
              // operatorParams, same as the single-word branch below -- a
              // multi-word rotate/shift (e.g. AES's words=4 rotate) carries
              // a real amount/direction; hardcoding {} here silently dropped
              // them, so resynthesis got the catalog defaults instead.
              const node = { kind: 'call', fn: fnName(b.type, b.params), params: operatorParams(b.type, b.params), args, words: b.words, row: b.row, col: b.col };
              // Tuple indices are numbered by ACTIVE-output position, not
              // physical word column: pseudocodeToGrid's multi-word branch
              // builds one out<k> port per argument (no spacer words), so a
              // physical index past the arg count (e.g. SP-box's word 12 of
              // 15 with spacers at 3/7/11) would reference a port that
              // never exists (confirmed: raw ELK "Referenced shape does not
              // exist"). For a fully-active block the two numberings are
              // identical, so the common case is unchanged.
              const outWords = Array.from({ length: b.words }, (_, w) => w).filter(
                (w) => blockPorts(b.type, b.params, w, b.words).bottom === 'out'
              );
              outWords.forEach((w, k) => {
                setPortValue(portKey(b.row, b.col, 'bottom', w), { kind: 'index', of: node, index: k + 1 });
              });
              computedComponents.add(b);
              changed = true;
            }
          }
          continue;
        }
        // A component's real output side is usually 'bottom', but not
        // always -- free_text (and anything else using the generic
        // portLeft/portRight/portBottom override mechanism, see
        // blockCatalog.js) can be laid sideways, output on 'left' or
        // 'right' instead, same as a compact diagram routinely draws it
        // (confirmed directly: classical_feistel_compact[rounds=1]'s own
        // F block does exactly this). Hardcoding 'bottom' here silently
        // recorded F's computed value at a port nothing actually reads
        // from, so F's *real* output (and everything downstream of it)
        // never got a value at all -- the fixed-point loop just quietly
        // stalled instead of erroring, which is why this showed up as an
        // incomplete pseudocode extraction, not a crash. `needed`'s
        // left/top/right/bottom order still matches the fixed
        // argument-order convention (see pseudocodeLayout.js's own
        // verticalArgIndex comment) for the common, unrotated case, since
        // 'bottom' is never itself an input there.
        const ports = scalarPorts.get(b) || blockPorts(b.type, b.params, 0, 1);
        const outSide = ['bottom', 'left', 'right', 'top'].find((s) => ports[s] === 'out');
        const outKey = outSide && portKey(b.row, b.col, outSide, 0);
        if (outKey && !portValue.has(outKey)) {
          const needed = ['left', 'top', 'right', 'bottom'].filter((s) => ports[s] === 'in').map((s) => portKey(b.row, b.col, s, 0));
          if (needed.every((k) => portValue.has(k))) {
            const physicalArgs = needed.map((k) => portValue.get(k));
            const args = operandOrder(b.params,physicalArgs.length).map(i=>physicalArgs[i]);
            const node = { kind: 'call', fn: fnName(b.type, b.params), params: operatorParams(b.type, b.params), args, row: b.row, col: b.col };
            setPortValue(outKey, node);
            changed = true;
          }
        }
        continue;
      }

      // wiring / double_wire / swap / multiblockpermutation: route-based,
      // exactly the adjacency-free part of connectivity -- reuse blockRoutes
      // (render.js) so double_wire/swap/multiblockpermutation's independent
      // routes are respected instead of assuming a single pass-through.
      if (type.family === 'wiring' || type.family === 'double_wire' || type.family === 'swap' || type.family === 'multiblockpermutation') {
        continue;
      }
    }


  }
  if (diagnostics) Object.assign(diagnostics, { iterations, portValues: portValue.size, iterationLimitReached: iterations > blocks.length && changed });

  // ---- completeness check ------------------------------------------------
  // The fixed-point loop above exits silently when it stalls (a value that
  // never propagates -- e.g. the historical sideways-output F-block bug, see
  // the component branch's own comment), which used to just drop the
  // affected output words from the emitted pseudocode with no error at all.
  // Every active output/intermediate_output word must have been emitted by
  // now. Only enforced when the grid has at least one real dataflow source
  // (an `input` block): a source-less catalog fixture (e.g. a single
  // `output` block on its own, asciiart/manual_examples/blocks/io/**) has
  // nothing to compute by construction and must keep returning '' rather
  // than throwing.
  const hasInputSource = blocks.some((b) => BLOCK_TYPES[b.type].family === 'io' && BLOCK_TYPES[b.type].kind === 'input');
  if (hasInputSource) {
    const missing = [];
    for (const b of blocks) {
      const type = BLOCK_TYPES[b.type];
      if (type.family !== 'io' || (type.kind !== 'output' && type.kind !== 'intermediate_output')) continue;
      const active = resolveActiveWords(b.params, b.words);
      for (const w of active) {
        if (!emitted.has(`${b.row},${b.col + w},0`)) missing.push(`${b.type} word at [${b.row}, ${b.col + w}]`);
      }
    }
    if (missing.length) {
      throw new Error(
        `gridToPseudocode: extraction incomplete -- ${missing.length} output word(s) never computed (stalled fixed point): ${missing.join('; ')}`
      );
    }
  }

  // A multi-word call's result is a tuple (see above) -- any node that
  // reaches one of its words via 'index' needs the call itself named and
  // emitted as its own assignment first, the same way output/
  // intermediate_output's own values are, since there's no way to write
  // "word i of this inline expression" without naming "this" first. Named
  // in row/col reading order (a multi-word call is always upstream of
  // anything indexing into it, so this is already a valid topological
  // order), one counter per function name so e.g. a diagram with several
  // mixcolumn instances gets mixcolumn1, mixcolumn2, ... instead of clashing.
  function collectMultiWordNodes(node, seen, list) {
    if (seen.has(node)) return;
    seen.add(node);
    if (node.kind === 'var') return;
    if (node.kind === 'index') {
      collectMultiWordNodes(node.of, seen, list);
      return;
    }
    if (node.words > 1) list.push(node);
    for (const arg of node.args) collectMultiWordNodes(arg, seen, list);
  }
  const multiWordNodes = [];
  const seenNodes = new Set();
  for (const a of assignments) collectMultiWordNodes(a.expr, seenNodes, multiWordNodes);
  multiWordNodes.sort(byReadingOrder);
  const nameCounters = new Map();
  for (const node of multiWordNodes) {
    const n = (nameCounters.get(node.fn) || 0) + 1;
    nameCounters.set(node.fn, n);
    const name = `${node.fn}${n}`;
    namedFor.set(node, name);
    assignments.push({ name, expr: node, row: node.row, col: node.col });
  }

  // ---- CSE: name any remaining node with 2+ distinct consumers ------------
  // A value that fans out to 2+ separately-written output/temp expressions
  // but was never explicitly tapped (no intermediate_output block) has, up
  // to this point, no name at all -- renderExpr would inline it as text on
  // every use, which also inlines whatever ITS OWN arguments are, silently
  // duplicating structure and amplifying a real 2-way leaf fan-out into a
  // 3-way one or worse (confirmed root cause of Lai Massey's own synthesis
  // failure: `F(xor(input1,input2))` feeds two different outputs directly,
  // with no tap in between). Naming it here means it round-trips as ONE
  // assignment referenced twice, matching what the diagram's own single
  // shared block plus a `split` already represents physically -- and gives
  // pseudocodeToGrid a real 'named' node to synthesize a genuine
  // intermediate_output tap for, the same physical shape needed to draw a
  // real split point at all.
  //
  // Mirrors collectDependencies' own traversal exactly (isRoot skips
  // counting a node against itself; an already-named node, e.g. a
  // multi-word tuple, is a traversal boundary -- it's already its own
  // assignment either way, so a reference to it is never expanded further
  // and never itself renamed) so this counts references over precisely the
  // same nodes renderExpr will actually re-expand, not a hypothetical
  // fuller graph. 'index' is never itself a CSE candidate -- word k of a
  // multi-word tuple is already compactly representable via its (always
  // pre-named, regardless of use count) `.of`.
  const refCounts = new Map();
  const refSeen = new Set();
  const sharedNodesInOrder = [];
  function collectRefCounts(node, isRoot) {
    if (node.kind === 'var') return;
    if (node.kind === 'index') {
      collectRefCounts(node.of, false);
      return;
    }
    if (!isRoot && namedFor.has(node)) return;
    if (!isRoot) {
      const prev = refCounts.get(node) || 0;
      refCounts.set(node, prev + 1);
      if (prev === 0) sharedNodesInOrder.push(node);
    }
    if (refSeen.has(node)) return;
    refSeen.add(node);
    for (const arg of node.args) collectRefCounts(arg, false);
  }
  for (const a of assignments) collectRefCounts(a.expr, true);
  const sharedNodes = sharedNodesInOrder.filter((node) => (refCounts.get(node) || 0) >= 2);

  const usedNames = new Set(assignments.map((a) => a.name));
  let tempCounter = 0;
  function freshTempName() {
    let name;
    do {
      tempCounter++;
      name = `temp[${tempCounter}]`;
    } while (usedNames.has(name));
    usedNames.add(name);
    return name;
  }
  for (const node of sharedNodes) {
    const name = freshTempName();
    namedFor.set(node, name);
    assignments.push({ name, expr: node, row: node.row, col: node.col });
  }

  // Assignments must appear in an order where every dependency (a variable
  // referenced in the expression, or a shared subexpression that's also
  // its own named assignment) comes before its use -- reading (row/col)
  // order alone doesn't guarantee this: a diagram can legitimately place a
  // computation's *source* block below/right of something that consumes
  // its result (e.g. ChaCha's quarterround, whose four outputs interleave
  // dependencies that don't follow row order). Topologically sort (Kahn's
  // algorithm), using reading order only to choose among assignments that
  // are equally ready, so independent branches still come out in a
  // human-friendly order.
  const assignmentNames = new Set(assignments.map((a) => a.name));

  // Mirrors renderExpr's own traversal (a named non-root node is printed as
  // just its name, not expanded) so the dependencies found here are exactly
  // the names renderExpr will actually print.
  function collectDependencies(node, isRoot, selfName, deps, seen) {
    if (!isRoot) {
      if (seen.has(node)) return;
      seen.add(node);
    }
    if (node.kind === 'var') {
      if (assignmentNames.has(node.name) && node.name !== selfName) deps.add(node.name);
      return;
    }
    if (node.kind === 'index') {
      if (namedFor.has(node.of)) {
        if (namedFor.get(node.of) !== selfName) deps.add(namedFor.get(node.of));
      } else {
        collectDependencies(node.of, false, selfName, deps, seen);
      }
      return;
    }
    if (!isRoot && namedFor.has(node)) {
      const depName = namedFor.get(node);
      if (depName !== selfName) deps.add(depName);
      return;
    }
    for (const arg of node.args) collectDependencies(arg, false, selfName, deps, seen);
  }

  const dependsOn = new Map(); // name -> Set<name>
  for (const a of assignments) {
    const deps = new Set();
    collectDependencies(a.expr, true, a.name, deps, new Set());
    dependsOn.set(a.name, deps);
  }
  const dependents = new Map(assignments.map((a) => [a.name, []])); // name -> [names depending on it]
  for (const a of assignments) {
    for (const dep of dependsOn.get(a.name)) dependents.get(dep).push(a.name);
  }
  const byName = new Map(assignments.map((a) => [a.name, a]));
  const remaining = new Map(assignments.map((a) => [a.name, dependsOn.get(a.name).size]));
  const ready = assignments.filter((a) => remaining.get(a.name) === 0).sort(byReadingOrder);
  const rank = new Map();
  let nextRank = 0;
  while (ready.length) {
    const a = ready.shift();
    rank.set(a.name, nextRank++);
    const unlocked = [];
    for (const depName of dependents.get(a.name)) {
      const left = remaining.get(depName) - 1;
      remaining.set(depName, left);
      if (left === 0) unlocked.push(byName.get(depName));
    }
    if (unlocked.length) {
      ready.push(...unlocked);
      ready.sort(byReadingOrder);
    }
  }
  // A cycle shouldn't happen for a valid (acyclic) dataflow -- if it somehow
  // does, fall back to reading order for the leftovers instead of losing them.
  for (const a of assignments) if (!rank.has(a.name)) rank.set(a.name, nextRank++);

  assignments.sort((a, b) => rank.get(a.name) - rank.get(b.name));

  function renderExpr(node) {
    if (node.kind === 'var') return node.name;
    if (namedFor.has(node) && !renderExpr.current.has(node)) return namedFor.get(node);
    if (node.kind === 'index') {
      const ofName = namedFor.get(node.of);
      return ofName ? `${ofName}[${node.index}]` : `${renderExpr(node.of)}[${node.index}]`;
    }
    const paramsText = Object.keys(node.params).length ? `[${Object.entries(node.params).map(([k, v]) => `${k}=${v}`).join(',')}]` : '';
    return `${node.fn}${paramsText}(${node.args.map(renderExpr).join(', ')})`;
  }
  renderExpr.current = new Set();

  const lines = assignments.map(({ name, expr }) => {
    renderExpr.current = new Set([expr]); // don't shortcut this expr to its own name while rendering it
    const text = `${name} = ${renderExpr(expr)}`;
    return text;
  });
  if (diagnostics) {diagnostics.expressionAssignments = assignments;diagnostics.inputNames=Object.fromEntries(inputNames);}
  const body = lines.join('\n');
  // A block's secrecy/word-size is only worth declaring when there's an
  // actual assignment body to synthesize -- a file with no output at all
  // (e.g. a single-block catalog fixture, even one with a secret or
  // multi-word input) must still return exactly '' here, since every
  // caller (generate-library.mjs, the comparison tools, this file's own
  // pseudocodeToGrid) treats an empty string as "no dataflow, nothing to
  // synthesize" -- a declarations-only, body-less string would silently
  // turn that into "has dataflow" and crash pseudocodeToGrid instead.
  return declLines.length && body ? `${declLines.join('\n')}\n\n${body}` : body;
}

// Give synthesized inputs compact, gap-free display labels. Outputs are
// different: their labels denote declared graph identities, not positions.
// If state-lane layout left them in semantic order [2,3,4,1], explicitly
// route those values into declaration order before drawing OUT[1]...OUT[4].
// This keeps both the visible circuit and a later pseudocode extraction
// truthful; merely relabelling the existing positions would not.
function finalizeSynthesizedIoIds(grid) {
  // Extraction omits visual styles. Restore value-bearing glyphs before
  // rendering: generic ROT/CONST labels cannot encode a direction, amount,
  // or constant, so decoding those labels changes the synthesized program.
  for (const block of grid.allBlocks()) {
    if (['rotate', 'shift', 'constant', 'variablerotate', 'variableshift'].includes(block.type)) {
      block.params.operator_style = 'symbol';
    }
  }
  const readingOrder = (a, b) => a.row - b.row || a.col - b.col;
  const inputs = grid.allBlocks().filter((block) => block.type === 'input').sort(readingOrder);
  inputs.forEach((block, index) => { block.params.id = `IN0_${index}`; });

  const outputs = grid.allBlocks().filter((block) => block.type === 'output').sort(readingOrder);
  for (const block of outputs) {
    if (block.words === 1 && /^output(?:\[\d+\])?$/.test(block.params.id || '')) {
      block.params.semanticName = block.params.id;
    }
  }
  const indexed = outputs.map((block) => {
    const match = /^output\[(\d+)\]$/.exec(block.params.semanticName || '');
    return match ? { block, name: block.params.semanticName, index: Number(match[1]) } : null;
  });
  const oneRow = new Set(outputs.map((block) => block.row)).size === 1;
  const scalarIndexed = outputs.length > 1 && indexed.every(Boolean)
    && outputs.every((block) => block.words === 1);

  if (oneRow && scalarIndexed) {
    const outputRow = outputs[0].row;
    const rowIsOnlyOutputs = grid.allBlocks().every((block) => block.row !== outputRow || block.type === 'output');
    const ordered = [...indexed].sort((a, b) => a.index - b.index);
    const columns = outputs.map((block) => block.col).sort((a, b) => a - b);
    const desired = new Map(ordered.map((entry, index) => [entry.name, columns[index]]));
    const needsRouting = indexed.some(({ block, name }) => block.col !== desired.get(name));

    if (rowIsOnlyOutputs && needsRouting) {
      outputs.forEach((block) => grid.removeBlock(block.row, block.col));
      const left = columns[0];
      const sourceByColumn = new Map(indexed.map(({ block, name }) => [block.col, name]));
      const destinationIndex = new Map(ordered.map(({ name }, index) => [name, index]));
      const params = {
        ...defaultParams('multiblockpermutation'),
        permutation: columns.map((col) => destinationIndex.get(sourceByColumn.get(col))).join(','),
        words: String(columns.at(-1) - left + 1),
        activeInputs: columns.map((col) => col - left).join(','),
        activeOutputs: columns.map((col) => col - left).join(','),
        borders: 'invisible',
      };
      grid.placeBlock(outputRow, left, 'multiblockpermutation', params);
      const row = outputRow + blockRowSpan('multiblockpermutation', params);
      for (const entry of ordered) {
        grid.placeBlock(row, desired.get(entry.name), 'output', {
          ...entry.block.params,
          semanticName: entry.name,
          id: `OUT[${entry.index}]`,
        });
      }
      return grid;
    }
  }

  outputs.forEach((block, index) => {
    const match = /^output\[(\d+)\]$/.exec(block.params.semanticName || '');
    block.params.id = match ? `OUT[${match[1]}]` : outputs.length === 1 ? 'OUT' : `OUT${index}`;
  });
  return grid;
}

// Declarations preamble: a contiguous run of `secret <name>`/`words <name,
// ...> = <N>` lines at the very top of the text (blank/`#`-comment lines
// tolerated, same as the assignment body below), carrying exactly the two
// per-input facts gridToPseudocode's own extraction can't otherwise express
// -- secrecy and multi-word grouping (see OPERATOR_PARAM_NAMES's own
// comment: both are dropped everywhere else in this file, `secrecy`
// entirely, word-grouping because each active word gets its own
// independently-numbered name with nothing linking them back into one
// physical block). Peeled off BEFORE parseAssignments ever sees the text,
// so that function's own grammar/errors are completely unaffected -- a
// `secret x` line has no `=` at all, and a `words x = N` line's left-of-`=`
// text is two tokens, which parseAssignments already rejects outright, so
// neither form could ever be mistaken for an assignment even without this
// pre-pass.
const DECL_NAME_RE = /^[A-Za-z_]\w*'*(?:\[\d+\])?$/;

function parseDeclarationLine(trimmed) {
  const m = /^(secret|words)\s+(.*)$/.exec(trimmed);
  if (!m) return null; // not a declaration line -- preamble ends here
  const [, kw, rest] = m;
  if (kw === 'secret') {
    const names = rest.split(',').map((s) => s.trim());
    if (names.some((n) => !DECL_NAME_RE.test(n))) throw new Error(`Invalid "secret" declaration: "${trimmed}"`);
    return { kind: 'secret', names };
  }
  const eq = rest.lastIndexOf('=');
  if (eq === -1) throw new Error(`Invalid "words" declaration (expected "words name[, name...] = N"): "${trimmed}"`);
  const names = rest.slice(0, eq).split(',').map((s) => s.trim());
  const countText = rest.slice(eq + 1).trim();
  if (names.some((n) => !DECL_NAME_RE.test(n)) || !/^\d+$/.test(countText)) throw new Error(`Invalid "words" declaration: "${trimmed}"`);
  const total = Number(countText);
  if (names.length === 0 || names.length > total) throw new Error(`"words" declaration lists ${names.length} name(s) but total is ${total}: "${trimmed}"`);
  return { kind: 'words', names, total };
}

// Returns { declarations: { secret: Set<name>, wordGroups: Map<name,
// {groupId, index, total, allIndices}> }, body } -- `body` is the
// remaining text, verbatim, from the first non-declaration line onward.
export function parseDeclarations(text) {
  const rawLines = text.split('\n');
  const secret = new Set();
  const wordGroups = new Map();
  let bodyStart = 0;
  for (let i = 0; i < rawLines.length; i++) {
    const trimmed = rawLines[i].trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      bodyStart = i + 1;
      continue;
    }
    const decl = parseDeclarationLine(trimmed); // may throw
    if (!decl) break;
    if (decl.kind === 'secret') {
      for (const n of decl.names) secret.add(n);
    } else {
      const groupId = decl.names[0];
      const allIndices = decl.names.map((_, k) => k);
      decl.names.forEach((n, index) => wordGroups.set(n, { groupId, index, total: decl.total, allIndices }));
    }
    bodyStart = i + 1;
  }
  return { declarations: { secret, wordGroups }, body: rawLines.slice(bodyStart).join('\n') };
}

// ---- parsing: "name[idx]? = ident[params]?(args)?", args recursive -------
// Trailing apostrophes allowed (not just \w*) so a free_text operator name
// like "F'" -- ordinary notation for a "related/derived function" (e.g.
// alternating Feistel's second round function) -- round-trips: gridToPseudocode
// emits a free_text block's own label verbatim as the function name (see
// fnName() above), so the parser must accept whatever that label legally is.
// Interior hyphens allowed (each '-' must be followed by more word chars,
// so a trailing '-' still ends the name): a free_text label like "SP-box"
// (gimli's own SP-box layer) becomes a function name / tuple name
// ("SP-box", "SP-box1") verbatim via fnName(), and this grammar has no
// arithmetic to be ambiguous against -- expressions are only names, calls,
// and bracket indexes; a literal '-' otherwise appears solely inside
// bracket param values (NUMBER_RE's negative numbers), parsed separately.
const IDENT_RE = /^[A-Za-z_]\w*(?:-\w+)*'*/;
const NUMBER_RE = /^-?\d+$/;

function skipWs(s, i) {
  while (i < s.length && /\s/.test(s[i])) i++;
  return i;
}

function parseIdent(s, i) {
  const m = IDENT_RE.exec(s.slice(i));
  if (!m) throw new Error(`Expected a name at "${s.slice(i, i + 20)}"`);
  return { text: m[0], pos: i + m[0].length };
}

// Reads raw text up to (not including) the given stop character, honoring
// no nesting -- bracket/paren contents in this grammar never nest a second
// bracket/paren of the same kind inside a single param value.
function readUntil(s, i, stop) {
  const start = i;
  while (i < s.length && s[i] !== stop) i++;
  if (i >= s.length) throw new Error(`Missing closing "${stop}" in "${s.slice(start)}"`);
  return { text: s.slice(start, i), pos: i };
}

function parseParamList(text) {
  const params = {};
  for (const pair of text.split(',')) {
    const [k, v] = pair.split('=').map((p) => p.trim());
    if (!k || v === undefined) throw new Error(`Malformed param "${pair}"`);
    // Hex constants are exact lexical tokens, including leading zeros.
    const number = Number(v);
    if (k !== 'value' && NUMBER_RE.test(v) && !Number.isSafeInteger(number)) throw new Error(`Unsafe numeric parameter ${k}`);
    params[k] = k !== 'value' && NUMBER_RE.test(v) ? number : v;
  }
  return params;
}

// One atom: IDENT, optionally followed by "[...]" (an index, if it's a bare
// integer, or call params, if it has "key=value" pairs) and/or "(args)".
function parseAtom(s, i) {
  i = skipWs(s, i);
  const { text: name, pos: p1 } = parseIdent(s, i);
  i = p1;
  let bracket = null;
  if (s[i] === '[') {
    const { text, pos } = readUntil(s, i + 1, ']');
    bracket = text.trim();
    i = pos + 1;
  }
  i = skipWs(s, i);
  if (s[i] === '(') {
    const args = [];
    i = skipWs(s, i + 1);
    if (s[i] !== ')') {
      while (true) {
        const { node, pos } = parseExpr(s, i);
        args.push(node);
        i = skipWs(s, pos);
        if (s[i] === ',') {
          i = skipWs(s, i + 1);
          continue;
        }
        break;
      }
    }
    if (s[i] !== ')') throw new Error(`Expected ")" at "${s.slice(i, i + 20)}"`);
    i = i + 1;
    const params = bracket ? parseParamList(bracket) : {};
    return { node: { kind: 'call', name, params, args }, pos: i };
  }
  // No call parens: a plain variable reference, optionally indexed.
  if (bracket !== null) {
    if (!NUMBER_RE.test(bracket)) throw new Error(`"${name}[${bracket}]" isn't a call (no arguments) or a valid index`);
    return { node: { kind: 'ref', name, index: Number(bracket) }, pos: i };
  }
  return { node: { kind: 'ref', name, index: null }, pos: i };
}

function parseExpr(s, i) {
  return parseAtom(s, i);
}

function refKey(name, index) {
  return index === null ? name : `${name}[${index}]`;
}

// Splits pseudocode text into { target: refKey, rhs: exprAst } assignments,
// tolerating blank lines and "#" comments like the grid-formula/formula
// parsers already do.
export function parseAssignments(text) {
  const lines = text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));
  const assignments = [];
  for (const line of lines) {
    const eq = line.indexOf('=');
    if (eq === -1) throw new Error(`Expected "name = expr" in line: "${line}"`);
    const lhs = line.slice(0, eq).trim();
    const rhsText = line.slice(eq + 1).trim();
    const { text: name, pos: p1 } = parseIdent(lhs, 0);
    let index = null;
    let after = skipWs(lhs, p1);
    if (lhs[after] === '[') {
      const { text: idxText, pos } = readUntil(lhs, after + 1, ']');
      if (!NUMBER_RE.test(idxText.trim())) throw new Error(`Invalid target index in line: "${line}"`);
      index = Number(idxText.trim());
      after = pos + 1;
    }
    if (skipWs(lhs, after) !== lhs.length) throw new Error(`Unexpected text after target name in line: "${line}"`);
    const { node: rhs, pos: rp } = parseExpr(rhsText, 0);
    if (skipWs(rhsText, rp) !== rhsText.length) throw new Error(`Unexpected trailing text in line: "${line}"`);
    assignments.push({ name, index, rhs, line });
  }
  return assignments;
}

// ---- resolving the AST into a shared-by-reference graph ------------------
// GraphNode: { kind: 'input', name } | { kind: 'call', typeName, params, args: GraphNode[] }
//          | { kind: 'named', label, inner: GraphNode } (an intermediate_output)
// Two references to the same target/leaf name resolve to the *same* object,
// which is exactly what lets the layout stage detect fan-out (a node needs
// a `split` the moment more than one consumer points at it).
export function buildGraph(assignments, declarations = { secret: new Set(), wordGroups: new Map() }) {
  const byKey = new Map(); // refKey -> assignment
  for (const a of assignments) byKey.set(refKey(a.name, a.index), a);

  const resolved = new Map(); // refKey -> GraphNode (memoized)
  const leaves = new Map(); // bare external name (not a target) -> GraphNode
  const resolving = new Set(); // cycle guard

  function isOutputName(name) {
    return name.toLowerCase() === 'output';
  }

  function resolveRef(name, index) {
    const key = refKey(name, index);
    if (resolved.has(key)) return resolved.get(key);
    if (byKey.has(key)) {
      if (resolving.has(key)) throw new Error(`Circular reference at "${key}"`);
      resolving.add(key);
      const a = byKey.get(key);
      const inner = resolveNode(a.rhs);
      // A target whose value is a multi-word call's own tuple result is
      // never a real named/intermediate_output tap -- it's exactly
      // gridToPseudocode's own synthesized name for such a call (e.g.
      // "mixcolumn1"), invented purely so later `name[k]` references can
      // reach a specific word (see the 'index' resolution above). It has
      // no corresponding grid block of its own; wrapping it in a 'named'
      // node here would give it a single generic port instead of the
      // multi-word call's own real per-word ports, breaking any indexed
      // reference into it.
      const isMultiWordTuple = inner.kind === 'call' && isMultiWordType(inner.typeName) && inner.args.length > 1;
      const node = isOutputName(name) || isMultiWordTuple ? inner : { kind: 'named', label: key, inner };
      resolving.delete(key);
      resolved.set(key, node);
      return node;
    }
    // "name[index]" with no assignment of its own, but bare "name" *is*
    // assigned -- this is gridToPseudocode's own shape for reaching one
    // word of a multi-word call's tuple result (renderExpr prints
    // `${ofName}[${node.index}]` as a bare reference, never as its own
    // assignment line -- see its 'index' case). Without this check, such
    // a reference would fall through to the leaf branch below and become
    // a disconnected fake input literally named "mc[1]" instead of
    // wiring to that word of the real call -- a silent correctness bug
    // (the diagram would still be "well-connected" per checkConnectivity,
    // since a stray leaf feeding a real consumer is structurally valid,
    // just wrong).
    if (index !== null && byKey.has(refKey(name, null))) {
      return { kind: 'index', of: resolveRef(name, null), index };
    }
    // Not a defined target -- an external leaf (an input, or any other
    // free-standing name). Memoized by its exact text so "input[2]" always
    // means the same leaf everywhere it's written. Tagged from the
    // declarations preamble (see parseDeclarations) when present -- a
    // declared-but-never-referenced name is simply never looked up here,
    // a silent no-op rather than an error.
    if (!leaves.has(key)) {
      const leaf = { kind: 'input', name: key };
      if (declarations.secret.has(key)) leaf.secret = true;
      const wordGroup = declarations.wordGroups.get(key);
      if (wordGroup) leaf.wordGroup = wordGroup;
      leaves.set(key, leaf);
    }
    return leaves.get(key);
  }

  function resolveNode(ast) {
    if (ast.kind === 'ref') return resolveRef(ast.name, ast.index);
    const typeName = BLOCK_TYPES[ast.name.toLowerCase()] && BLOCK_TYPES[ast.name.toLowerCase()].family === 'component' ? ast.name.toLowerCase() : 'free_text';
    const args = ast.args.map(resolveNode);
    const params = typeName === 'free_text' ? { text: ast.name, ...ast.params } : { ...ast.params };
    return { kind: 'call', typeName, params, args };
  }

  // Every target literally named "output"/"output[n]" needs an actual
  // `output` grid block wired to its inner node's value, *in addition* to
  // that value's ordinary use elsewhere if it's reused (see
  // gridToPseudocode's own namedFor/CSE comment for the mirror-image case).
  // Every other target is a `named` node already routable in the graph
  // (it has its own real bottom-out), so it needs no separate attachment.
  const targetOrder = assignments.map((a) => {
    const node = resolveRef(a.name, a.index);
    const name = refKey(a.name, a.index);
    const isOutput = isOutputName(a.name);
    // A declared output word-group (see parseDeclarations) is looked up
    // by the target's own name, same as an input leaf's -- unlike inputs,
    // an output target has no GraphNode identity of its own to tag (it's
    // a plain targetOrder entry), so the tag lives here instead.
    const wordGroup = isOutput ? declarations.wordGroups.get(name) : undefined;
    return { name, node, isOutput, wordGroup };
  });

  // A word group's secrecy is the OR across whichever of its members were
  // actually declared secret -- robust even if a hand-written declaration
  // only tags one word of a group (matches `secrecy` being one param
  // shared by the whole physical block, not per-word).
  const groupMembers = new Map();
  for (const leaf of leaves.values()) {
    if (!leaf.wordGroup) continue;
    const gid = leaf.wordGroup.groupId;
    if (!groupMembers.has(gid)) groupMembers.set(gid, []);
    groupMembers.get(gid).push(leaf);
  }
  for (const members of groupMembers.values()) {
    const anySecret = members.some((m) => m.secret);
    for (const m of members) m.groupSecret = anySecret;
  }

  return { targetOrder, leaves };
}

// ---- shared argument/port conventions --------------------------------
// Which slot (by argument index) a call's arguments attach to -- WEST for
// indices before the vertical slot, NORTH for the vertical slot itself,
// EAST for indices after it (see verticalArgIndex below) -- matching
// gridToPseudocode's own extraction, which reads a component's ports back
// in a fixed ['left','top','right'] order to reconstruct original
// argument order. This convention is load-bearing for round-trip
// correctness (non-commutative operations, e.g. modsub, depend on
// argument order surviving the round trip) and must stay identical on
// both the extraction and synthesis sides -- see pseudocodeLayout.js,
// which uses these same two functions when building its own layout graph.
// A genuine "one argument per word" type (mixcolumn, shiftrows, ...) is
// built via blockCatalog.js's multiWordComponent(), which always hard-
// codes `inputs: 1` (one port per word, regardless of word count) --
// unlike an ordinary component (xor, modadd, rotate, ...) that merely
// gained an *optional* word-merging `words` param (several physical
// word-slots drawn as one wider box around the *same* semantic
// argument(s), not one argument per word). `inputs` alone tells them
// apart: it's a literal `1` only for the former (for the latter it's
// either a function, as with xor/and/or's configurable inputs=2|3, or a
// literal that isn't 1, as with modadd/variablerotate's fixed inputs=2).
// Checking only "has a words param" (the pre-existing, now-too-loose
// definition) started misclassifying every word-bearing 2-arg component
// as multi-word the moment `words` became a generic component param --
// confirmed directly: it broke pseudocodeToGrid's ELK graph construction
// for ordinary calls like `xor(a, b)`, which have nothing to do with
// per-word arguments at all.
export function isMultiWordType(typeName) {
  const type = BLOCK_TYPES[typeName];
  return type.inputs === 1 && type.params.some((p) => p.name === 'words');
}

// Which slot (by argument index) is this call's vertical/trunk argument --
// see the file-level comment above for the [left, top, right] convention.
export function verticalArgIndex(argCount) {
  if (argCount === 1) return 0;
  if (argCount === 2) return 1;
  if (argCount === 3) return 1;
  return -1; // 0-arg, or multi-word (handled separately -- every word is its own "vertical")
}

// ---------------------------------------------------------- code -> grid --
// Parses pseudocode into an expression DAG (parseAssignments/buildGraph,
// above -- shared node identity is how a reused value's fan-out is
// represented). `semantic-auto` runs the integrated semantic-pattern and
// human-drawing engines first, falling back to pseudocodeLayout.js and ELK
// only when the experimental router explicitly rejects a shape. See that
// file for the general fallback layout/drawing logic and for why: an earlier hand-rolled router that
// interleaved placement and routing incrementally, with only local
// lookahead, proved too fragile to keep patching -- see project history.
// Other `strategy` values (see pseudocodeLayout.js's buildElkGraph) pick which
// whole-graph vertical-argument rule lays out 2-argument calls -- 'arg0'
// (default, matches every existing caller's behavior exactly) unless the
// caller opts into 'successor-count' or 'catalog-default' instead. This is
// the one hook a caller (e.g. the round-trip harness) has for trying a
// genuinely different, still general layout rule per diagram, rather than
// hardcoding a per-file exception into the layout logic itself.
//
// `diagnostics`, when passed, is filled in (mutated, not replaced) with
// `{ strategy, alignment }` -- `alignment` is alignDeclaredOutputs' own
// status object (see its comment) describing whether declared outputs
// needed realigning with their same-numbered inputs and whether that
// actually happened. Opt-in and side-channel rather than a second return
// value so every existing caller (the app's own "Compile to grid" button,
// the round-trip harness) is unaffected; generate-library.mjs is the
// motivating caller, recording this as library metadata so a layout
// oddity (misaligned columns, a missing permutation) can be traced back
// to *why*, not just observed.
//
// Preserve source operand order with a visible local binding when a compact
// Boolean route chooses another physical port order. No original graph is
// needed by the exported-text decoder; @21/@312 are the entire local contract.
function bindBooleanPorts(text, grid, inputAliases = new Map()) {
  const parsed=parseDeclarations(text);
  const graph=buildGraph(parseAssignments(parsed.body),parsed.declarations);
  const trace={}; gridToPseudocode(grid,{diagnostics:trace});
  const assignments=new Map(trace.expressionAssignments.map(a=>[a.name,a.expr]));
  const intern=new Map(), memoSource=new Map(), memoActual=new Map();
  const unwrap=n=> {
    while(n.kind==='named')n=n.inner;
    if(n.kind==='index'&&n.index===1&&n.of.kind==='named') {
      const owner=unwrap(n.of);
      if(owner.kind==='call'&&!(isMultiWordType(owner.typeName)&&owner.args.length>1))return owner;
    }
    return n;
  };
  const resolve=n=>n.kind==='var'&&assignments.has(n.name)?resolve(assignments.get(n.name)):n;
  function digest(raw,actual=false) {
    const n=actual?resolve(raw):unwrap(raw), memo=actual?memoActual:memoSource;
    if(memo.has(n))return memo.get(n);
    let record;
    if((actual&&n.kind==='var')||n.kind==='input')record=['input',actual?(inputAliases.get(n.name)||n.name):n.name];
    else if(n.kind==='index')record=['index',n.index,digest(n.of,actual)];
    else {
      const type=actual?(BLOCK_TYPES[n.fn]?.family==='component'?n.fn:'free_text'):n.typeName;
      const params=actual&&type==='free_text'?{...n.params,text:n.fn}:n.params;
      const defaults=defaultParams(type);
      const names=new Set([...Object.keys(params),...(OPERATOR_PARAM_NAMES[type]||[])]);
      const fields=[...names].sort().map(k=>[k,params[k]??defaults[k]]).filter(([,v])=>v!==undefined);
      const args=n.args.map(a=>digest(a,actual));
      if(['xor','and','or'].includes(type))args.sort((a,b)=>a-b);
      record=['call',type,fields,args];
    }
    const key=JSON.stringify(record);if(!intern.has(key))intern.set(key,intern.size);
    const value=intern.get(key);memo.set(n,value);return value;
  }
  const patched=new Map(), seen=new Map();
  function bind(sourceRaw,actualRaw) {
    const source=unwrap(sourceRaw),actual=resolve(actualRaw);
    if(digest(source)!==digest(actual,true))throw new Error('Compact route changes more than Boolean port order');
    if(!seen.has(source))seen.set(source,new Set());
    if(seen.get(source).has(actual))return;seen.get(source).add(actual);
    if(source.kind==='input')return;
    if(source.kind==='index'){bind(source.of,actual.of);return;}
    if(['xor','and','or'].includes(source.typeName)) {
      const available=actual.args.map((n,i)=>({n,i,key:digest(n,true)}));
      const pairs=source.args.map(n=> {
        const key=digest(n),index=available.findIndex(a=>a.key===key);
        if(index<0)throw new Error('Missing Boolean operand');
        return {source:n,...available.splice(index,1)[0]};
      });
      const block=grid.getBlockAt(actual.row,actual.col);
      if(!block||block.words!==1)throw new Error('Binding requires scalar Boolean gate');
      const existing=operandOrder(block.params,actual.args.length);
      const order=pairs.map(p=>existing[p.i]);
      const label=order.every((v,i)=>v===i)?'':order.map(n=>n+1).join('');
      if(patched.has(block)&&patched.get(block)!==label)throw new Error('Conflicting shared Boolean operand order');
      patched.set(block,label);
      pairs.forEach(p=>bind(p.source,p.n));
    } else source.args.forEach((arg,i)=>bind(arg,actual.args[i]));
  }
  for(const target of graph.targetOrder.filter(t=>t.isOutput)) {
    const name=target.name==='output[1]'&&!assignments.has(target.name)?'output':target.name;
    const actual=assignments.get(name)||assignments.get(name==='output'?'output[1]':name);
    if(!actual)throw new Error('Missing declared output during binding');
    bind(target.node,actual);
  }
  for(const [block,order]of patched)block.params.operand_order=order;
}

// Compare ordered computations with shared structural interning, without
// expanding reused DAGs. This is a routing guard, not an independent evaluator.
function assertOrderedGrid(sourceText, grid, {bind = true} = {}) {
  const inputAliases = new Map();
  const inputGraph = text => { const {body,declarations}=parseDeclarations(text); return buildGraph(parseAssignments(body),declarations); };
  const sourceInputs=[...inputGraph(sourceText).leaves.values()];
  if(sourceInputs.some(n=>!/^input(?:\[\d+\])?$/.test(n.name))) {
    const actualInputs=[...inputGraph(gridToPseudocode(grid)).leaves.values()];
    for(const leaf of sourceInputs) {
      const role=Boolean(leaf.secret||leaf.groupSecret);
      const sourcePool=sourceInputs.filter(n=>Boolean(n.secret||n.groupSecret)===role);
      const actualPool=actualInputs.filter(n=>Boolean(n.secret||n.groupSecret)===role);
      if(sourcePool.length!==actualPool.length)throw new Error('Input roles changed during layout');
      const natural=(a,b)=>a.name.localeCompare(b.name,'en',{numeric:true});
      sourcePool.sort(natural);actualPool.sort(natural);
      inputAliases.set(actualPool[sourcePool.indexOf(leaf)].name,leaf.name);
    }
  }
  const intern = new Map();
  const group = g => g ? [g.index, g.total] : null;
  const signature = (text, actual = false) => {
    const {body, declarations} = parseDeclarations(text);
    const graph = buildGraph(parseAssignments(body), declarations);
    const memo = new Map();
    function visit(n) {
      if (n.kind === 'named') return visit(n.inner);
      if (n.kind === 'index' && n.index === 1 && n.of.kind === 'named') return visit(n.of.inner);
      if (memo.has(n)) return memo.get(n);
      let record;
      if (n.kind === 'input') record = ['input',actual?(inputAliases.get(n.name)||n.name):n.name,Boolean(n.secret || n.groupSecret),group(n.wordGroup)];
      else if (n.kind === 'index') record = ['index',n.index,visit(n.of)];
      else {
        const defaults = defaultParams(n.typeName);
        const names = new Set([...Object.keys(n.params),...(OPERATOR_PARAM_NAMES[n.typeName] || [])]);
        const params = [...names].sort().map(k => [k,n.params[k] ?? defaults[k]]).filter(([,v]) => v !== undefined);
        record = ['call',n.typeName,params,n.args.map(visit)];
      }
      const key = JSON.stringify(record);
      if (!intern.has(key)) intern.set(key,intern.size);
      const id = intern.get(key); memo.set(n,id); return id;
    }
    return JSON.stringify(graph.targetOrder.filter(t => t.isOutput).map(t =>
      [t.name === 'output' ? 'output[1]' : t.name,group(t.wordGroup),visit(t.node)])
      .sort((a,b) => a[0].localeCompare(b[0],'en',{numeric:true})));
  };
  if (signature(sourceText) !== signature(gridToPseudocode(grid),true)) {
    if (!bind) throw new Error('Exported ASCII changes ordered operands or represented semantics.');
    bindBooleanPorts(sourceText,grid,inputAliases);
    if (signature(sourceText) !== signature(gridToPseudocode(grid),true)) throw new Error('Routing changed ordered operands or represented semantics.');
  }
  return grid;
}

export async function pseudocodeToGrid(text, { strategy = 'arg0', diagnostics } = {}) {
  // Only the consolidated primary route promises ordered fidelity. Legacy
  // experimental routes retain their behavior for comparison and ablation.
  const faithful = grid => {
    if (strategy !== 'semantic-auto') return grid;
    try {
      assertOrderedGrid(text, grid);
      assertOrderedGrid(text, decodeGrid(renderGrid(grid)), {bind:false});
      return grid;
    }
    catch (error) {
      if (diagnostics) (diagnostics.rejections ||= []).push({engine:diagnostics.engine,
        error:error.message,pseudocode:gridToPseudocode(grid)});
      throw error;
    }
  };
  const { declarations, body } = parseDeclarations(text);
  const assignments = parseAssignments(body);
  if (assignments.length === 0) throw new Error('Pseudocode is empty.');
  let { targetOrder, leaves } = buildGraph(assignments, declarations);
  let effectiveStrategy = strategy;
  if (strategy === 'semantic-auto' || strategy === 'human-drawing') {
    try {
      const grid = graphToGridHumanDrawing(targetOrder, { diagnostics });
      if (diagnostics) Object.assign(diagnostics, { strategy, effectiveStrategy: diagnostics.engine });
      return faithful(finalizeSynthesizedIoIds(grid));
    } catch (err) {
      if (strategy === 'human-drawing') throw err;
      // The human-drawing engine intentionally mutates a few recognized
      // graph shapes (notably swaps). Rebuild before fallback so the
      // conservative engine always receives the pristine parsed graph.
      ({ targetOrder, leaves } = buildGraph(assignments, declarations));
      if (diagnostics) {
        diagnostics.humanDrawing = { fallback: true, error: err.message };
        if (diagnostics.semantic?.matched) diagnostics.rejectedSemantic = {...diagnostics.semantic, reason: err.message};
        diagnostics.semantic = { matched: false };
      }
      try {
        const grid = graphToGridDirectBus(targetOrder, { diagnostics });
        if (diagnostics) Object.assign(diagnostics, { strategy, effectiveStrategy: 'direct-bus' });
        return faithful(finalizeSynthesizedIoIds(grid));
      } catch (directError) {
        ({ targetOrder, leaves } = buildGraph(assignments, declarations));
        if (diagnostics) diagnostics.directBus = { fallback: true, error: directError.message };
        try {
          const grid = graphToGridConservative(targetOrder, { diagnostics });
          if (diagnostics) Object.assign(diagnostics, { strategy, effectiveStrategy: 'conservative-bus' });
          return faithful(finalizeSynthesizedIoIds(grid));
        } catch (conservativeError) {
          // Preserve the established whole-graph engine as the final
          // backstop for any future graph shape both bus strategies reject.
          ({ targetOrder, leaves } = buildGraph(assignments, declarations));
          effectiveStrategy = 'arg0';
          if (diagnostics) diagnostics.conservativeBus = { fallback: true, error: conservativeError.message };
        }
      }
    }
  }
  const { graph, meta, idOf, outputIdByName } = buildElkGraph(targetOrder, effectiveStrategy);
  const { grid, nodeCell } = await layoutToGrid(graph, meta, effectiveStrategy, { targetOrder, idOf, outputIdByName });
  const alignment = alignDeclaredOutputs(grid, targetOrder, leaves, idOf, outputIdByName, nodeCell, meta);
  if (diagnostics) Object.assign(diagnostics, { strategy, effectiveStrategy, alignment });

  const connectivity = checkConnectivity(grid);
  if (!connectivity.wellConnected) {
    const first = connectivity.problems[0];
    throw new Error(`Routing produced an invalid diagram (${first.message}). This shape isn't supported by this synthesizer yet.`);
  }

  return faithful(finalizeSynthesizedIoIds(grid));
}
