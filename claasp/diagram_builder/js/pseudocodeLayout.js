// ELK-based replacement for pseudocodeToGrid's placement/routing engine.
// See project history for why: the old hand-rolled router (place/resolve/
// relay/relocateDown/descendUntilFree/travelRow, with a manual `reserved`
// bookkeeping map) interleaved placement and routing in one incremental
// pass with only local lookahead, which made it fragile -- several
// targeted fixes to its core failure mode either did nothing or caused
// real regressions. This module instead does what standard layered-graph-
// drawing tools (Graphviz/dagre/ELK) do: lay out the *whole* graph
// holistically first (layering, ordering, coordinate assignment, edge
// routing), then draw from an already-fully-determined result -- no
// per-node "hope this column stays free" bookkeeping needed at all.
//
// `buildGraph()`'s parsed DAG (pseudocode.js) is consumed unchanged; only
// the layout/drawing half is replaced. The port-per-argument convention
// (which argument is "vertical" vs "lateral") is NOT changed here -- it's
// load-bearing for gridToPseudocode's own extraction (untouched), which
// reconstructs original argument order by reading ports back in a fixed
// left/top/right order. This module only changes *coordinates and wire
// paths*, never which port an argument attaches to.
import ELK from '../vendor/elk-esm.js';
import { BLOCK_TYPES, defaultParams, setComponentSidePort, REWIRE_PORTS } from './blockCatalog.js';
import { Grid } from './grid.js';
import { isMultiWordType, verticalArgIndex } from './pseudocode.js';
import { checkConnectivity, OPPOSITE_SIDE as OPPOSITE } from './connectivity.js';

// Verified empirically against real elkjs (see project history) -- do not
// "simplify" these back to defaults without re-checking against a real
// layout result. In particular `elk.spacing.edgeNode` (NOT namespaced
// under `elk.layered.*` like its neighbors, easy to miss) defaults to 10
// and reserves that much lateral room for any edge arriving at a WEST/EAST
// port -- which is every 2/3-argument call's lateral argument, i.e. most
// real diagrams -- and `elk.layered.spacing.nodeNodeBetweenLayers` must be
// 0, not 1, or a spurious extra row appears between every directly-
// chained pair of blocks.
const ELK_OPTIONS = {
  'elk.algorithm': 'layered',
  'elk.direction': 'DOWN',
  'elk.edgeRouting': 'ORTHOGONAL',
  'elk.padding': '[top=0,left=0,bottom=0,right=0]',
  'elk.spacing.nodeNode': '1',
  'elk.layered.spacing.nodeNodeBetweenLayers': '1',
  'elk.spacing.edgeNode': '1',
  'elk.layered.spacing.edgeNodeBetweenLayers': '0',
  'elk.spacing.portPort': '1',
  // ELK's default (`separateConnectedComponents: true`) lays out each
  // disconnected piece of the pseudocode graph independently, then packs
  // the results -- which stacked them vertically in testing rather than
  // placing them side by side, and (worse) meant the FIRST/LAST layer
  // constraints on inputs/outputs (see buildElkGraph) only held *within*
  // each piece, not across all of them (e.g. two unrelated outputs at
  // different depths in their own pieces no longer landed on the same
  // row). Disabling this treats the whole graph as one layering problem,
  // so those constraints apply globally, exactly as intended.
  'elk.separateConnectedComponents': 'false',
  // Lets every top-level input's `elk.position` hint (see buildElkGraph's
  // inputOrderHint) act as a soft left-right ordering preference within
  // its own layer, instead of the crossing-minimizer freely reordering
  // inputs by pure edge-crossing cost. Confirmed directly (throwaway elkjs
  // experiment, then the real corpus) that nodes with no position hint at
  // all are unaffected -- unlike the much blunter, tried-and-reverted
  // `considerModelOrder.strategy` + `forceNodeModelOrder` combination,
  // which forces model order onto *every* node and severely regressed the
  // corpus (see project history).
  'elk.layered.crossingMinimization.semiInteractive': 'true',
};

// Collects every GraphNode reachable from `node` (itself included),
// stopping at leaves -- used by riskyShare below.
function collectNodes(node, into) {
  if (into.has(node)) return into;
  into.add(node);
  if (node.kind === 'call') node.args.forEach((a) => collectNodes(a, into));
  else if (node.kind === 'named') collectNodes(node.inner, into);
  else if (node.kind === 'index') collectNodes(node.of, into);
  return into;
}

// If `node` is a leaf itself, or a chain of 1-argument calls leading
// directly to one (e.g. `F(input)`), returns that leaf; else null. A
// *deep* shared node two arguments' subtrees both happen to reach (e.g.
// `modadd(rotate(input1), input2)` vs. `rotate2(input2)` -- both reach
// `input2`, several levels down on one side) is not the risk this file
// cares about; only a shared leaf sitting at the very top of one
// argument's own chain is.
function trivialChainLeaf(node) {
  let n = node;
  while (n.kind === 'call' && n.args.length === 1) n = n.args[0];
  return n.kind === 'input' ? n : null;
}

// True exactly for the shape that collapses drawFanoutGroup's shortest
// sibling path (see the vertical-argument flip's own comment for why):
// one argument is a leaf, or a trivial 1-arg chain topped by one (e.g.
// `F(input)`), and that *same* leaf is also reachable from the other
// argument's subtree (e.g. the other argument just *is* that leaf, as in
// `xor(F(input), input)`). Checked both ways since either argument could
// end up the flipped-to-vertical one.
//
// Tried narrowing this to check only arg0 (since the flip always makes
// arg0 -- never arg1 -- vertical, so only arg0's own triviality should
// matter): that unblocked Speck's own `xor(output[1], rotate2(input2))`
// as hoped, but hit a *different*, genuine crash the moment it was
// exercised for real ("Non-adjacent cells in a routed path") and dropped
// the corpus from 34/55 to 33/55 -- a real, separately-scoped fan-out/
// routing bug this flip must not go out of its way to trigger either.
// Reverted to the symmetric check; xor stays unflipped in that shape.
// Distinct GraphNodes reachable from targetOrder -- the size predicate for
// the 'relaxed-flip' gate (see buildElkGraph). The dense multi-round
// primitives sit at 100+ nodes; every near-exact small construction is
// well under this.
const RELAXED_FLIP_MAX_NODES = 40;
function countGraphNodes(targetOrder) {
  const seen = new Set();
  for (const t of targetOrder) collectNodes(t.node, seen);
  return seen.size;
}

function riskyShare(a, b) {
  const leafA = trivialChainLeaf(a);
  if (leafA && collectNodes(b, new Set()).has(leafA)) return true;
  const leafB = trivialChainLeaf(b);
  if (leafB && collectNodes(a, new Set()).has(leafB)) return true;
  return false;
}

// Two general, whole-graph vertical-argument strategies, tried as outright
// *replacements* for each other in project history: 'arg0' (always prefer
// the first textual argument -- today's default) vs 'successor-count' (the
// sibling CLAASP asciiart compiler's own column-inheritance rule, fewer
// other consumers wins the vertical slot, claasp/compilers/asciiart/
// columns.py). Neither dominates the other -- confirmed directly, not
// assumed: for Speck's own `modadd(rotate(input1), input2)` they agree
// (rotate's result has 1 consumer, input2 has 2, so successor-count also
// picks rotate's result vertical). But swapping to successor-count as a
// full replacement regressed chacha_quarterround.asciiart (34/55 -> 33/55):
// its `xor(modaddResult, input4)` has the same "reused value" shape as
// Speck's xor (the one riskyShare leaves unflipped either way), and
// successor-count's semantically-motivated pick (input4, 1 consumer,
// vertical) lands on a *different* rough edge of drawFanoutGroup's own
// routing than arg0's pick does. Neither rule is safe against every shape
// this drawing code can be given -- each avoids a different weak spot. So
// instead of picking one, both are kept as selectable `strategy` values
// (see buildElkGraph) -- the round-trip harness can try each per diagram
// and keep whichever one actually works for that file, without hardcoding
// per-file exceptions into the layout logic itself.
function successorCounts(targetOrder) {
  const counts = new Map();
  const bump = (node) => counts.set(node, (counts.get(node) || 0) + 1);
  function visit(node) {
    if (node.kind === 'call') node.args.forEach((arg) => { bump(arg); visit(arg); });
    else if (node.kind === 'named') visit(node.inner);
    else if (node.kind === 'index') visit(node.of);
  }
  for (const t of targetOrder) visit(t.node);
  return (node) => counts.get(node) || 0;
}

// Which declared word-groups (see buildGraph's own wordGroup tagging from
// parseDeclarations) get drawn as ONE shared, fixed-position multi-word
// node -- either an input leaf's own group, or an output target's own
// group. Today: ALL of them. See the historical note inside the function
// for the two empirically-derived safety conditions that used to gate
// this, and the corpus re-measurement that retired them.
function safeWordGroups(targetOrder) {
  // Historical note: this used to DECLINE sharing under two empirically
  // derived conditions -- (1) a group with 2+ independently-reused members
  // and (2) any multi-word call anywhere in the graph -- both measured
  // against the drawing engine as it was BEFORE lane-aware gap
  // quantization, forcedLastStep approach-side enforcement, wrong-side
  // corridor lifting, divergence-cell reservation and last-resort
  // rerouting existed. Re-measured against the full 79-file corpus with
  // that stack in place: sharing EVERY declared group flips all 6
  // declaration-loss files (unbalanced_feistel_explicit_f_function x2,
  // even_mansour_double_sbox_mixcolumn x4) from 'different' to
  // 'equivalent' with zero per-file regressions and exact/mirror counts
  // unchanged -- the placement-freedom problems sharing used to trigger
  // are exactly what those later fixes absorbed. So every declared group
  // is now shared; the declaration-aware equivalence check
  // (roundTripStrategies.mjs's classify, which hashes word-group tags)
  // is what would catch this decision silently regressing again.
  const safe = new Set();
  function visit(node) {
    if (node.kind === 'input' && node.wordGroup) safe.add(node.wordGroup.groupId);
    else if (node.kind === 'call') node.args.forEach(visit);
    else if (node.kind === 'named') visit(node.inner);
    else if (node.kind === 'index') visit(node.of);
  }
  for (const t of targetOrder) {
    visit(t.node);
    if (t.isOutput && t.wordGroup) safe.add(t.wordGroup.groupId);
  }
  return safe;
}
// A `free_text` call is the one catalog type legitimately used BOTH as an
// ordinary 1-word, N-argument component (e.g. NORX's own round function
// `h(a, b)`, via the generic portLeft/portRight override mechanism) AND as
// a genuinely wide multi-word placeholder -- its catalog entry declares
// both `inputs:1` and a `words` param unconditionally (blockCatalog.js),
// so `isMultiWordType('free_text')` can't itself tell the two apart.
// Confirmed by direct reproduction: a >1-arg `free_text` call whose result
// is never indexed (nothing ever reads word k of it) was still being built
// with per-word in/out ports (see the `multiWord` branch below), which
// leaves its plain, unindexed `.out` port referenced by `outPortOf` but
// never created -- ELK itself throws a raw
// `JsonImportException: Referenced shape does not exist` for exactly this
// shape. This collects which call nodes are ever the `.of` of some `index`
// GraphNode (buildGraph's own marker for "word k of this call's tuple
// result is read somewhere") so the multi-word branch can be skipped for
// an unindexed free_text call -- every other multi-word catalog type is
// only ever given >1 arg when it genuinely means a tuple result (mirrored
// by buildGraph's own resolveRef, which unconditionally treats any
// isMultiWordType call as tuple-shaped regardless of indexing), so this
// check is deliberately scoped to `free_text` only, not applied generally.
function indexedCallNodes(targetOrder) {
  const indexed = new Set();
  function visit(node) {
    if (node.kind === 'call') node.args.forEach(visit);
    else if (node.kind === 'named') visit(node.inner);
    else if (node.kind === 'index') {
      indexed.add(node.of);
      visit(node.of);
    }
  }
  for (const t of targetOrder) visit(t.node);
  return indexed;
}

// ---------------------------------------------------------------- graph --

// Builds the ELK input graph from buildGraph()'s targetOrder (see
// pseudocode.js). Returns { graph, meta, idOf, outputIdByName }: meta maps
// every ELK node id to { kind, typeName, params, words } describing the
// actual grid block to place there; idOf maps a GraphNode (as seen by
// buildGraph, e.g. an `input` leaf) to its elk node id -- needed to look
// its placed cell back up after layout (see alignDeclaredOutputs);
// outputIdByName maps a target's refKey (e.g. "output[2]") to the elk id
// of the `output` node created for it (outputs never go through
// ensureNode/idOf since they're not a shared GraphNode -- see the
// targetOrder loop below).
// `strategy` selects the whole-graph vertical-argument rule for 2-argument
// calls (see the comment above successorCounts): 'arg0' (default, matches
// pre-existing behavior exactly), 'successor-count', or 'catalog-default'
// (the flip is disabled entirely, always falling back to
// verticalArgIndex(argCount) -- a genuine zero-heuristic baseline).
export function buildElkGraph(targetOrder, strategy = 'arg0') {
  const idOf = new Map(); // GraphNode -> elk node id
  const outputIdByName = new Map(); // targetOrder[i].name -> elk node id
  const meta = new Map(); // id -> block description
  const groupNodeIds = new Map(); // wordGroup.groupId -> elk node id (shared multi-word input OR output node -- groupIds are disjoint namespaces, always the group's first input or output name)
  const children = [];
  const edges = [];
  let nextId = 0;
  let nextEdge = 0;
  const successorCountOf = strategy === 'successor-count' ? successorCounts(targetOrder) : null;
  const indexedCalls = indexedCallNodes(targetOrder);
  const shareableWordGroups = safeWordGroups(targetOrder);
  const useCount = nodeUseCounts(targetOrder);
  const secretPresent = hasSecretInput(targetOrder);
  // 'relaxed-flip': behaves exactly like 'arg0' except the two flip guards
  // (riskyShare, arg0ReusedElsewhere) are skipped -- both were tuned
  // empirically against the drawing engine BEFORE recursive fan-out
  // conflict detection, the 3-way split, lane-aware quantization,
  // forcedLastStep and last-resort rerouting existed (same situation
  // safeWordGroups' retired conditions were in). Gated to small graphs:
  // the guards' crash shapes live in the dense already-failing files,
  // where retrying them only burns reroute time -- above the threshold
  // this strategy intentionally degenerates to plain 'arg0' behavior
  // (identical output, so best-of tie-breaking keeps the earlier winner).
  const relaxedFlip = strategy === 'relaxed-flip' && countGraphNodes(targetOrder) <= RELAXED_FLIP_MAX_NODES;

  function makePort(nodeId, name, side) {
    return { id: `${nodeId}.${name}`, width: 0.01, height: 0.01, layoutOptions: { 'elk.port.side': side } };
  }
  function makeFixedPosPort(nodeId, name, x, y) {
    return { id: `${nodeId}.${name}`, x, y, width: 0.01, height: 0.01 };
  }

  // Every top-level input (word-group or plain) gets an `elk.position`
  // hint proportional to its own creation order, i.e. its left-to-right
  // reading order in the original pseudocode text (buildGraph's leaves
  // are created in first-encountered order). Combined with
  // ELK_OPTIONS' `elk.layered.crossingMinimization.semiInteractive`, ELK
  // treats this as a soft preference for relative left-right order among
  // *only* the nodes that carry it -- confirmed directly (throwaway elkjs
  // experiment) that this is enough to keep a public input to the left of
  // a secret one without needing to pin every other node's position too,
  // unlike the much blunter (and, tried and reverted: severely
  // corpus-regressing) `considerModelOrder.strategy` +
  // `crossingMinimization.forceNodeModelOrder` global combination. Never
  // overrides FIRST-layer assignment (still separate, via
  // layerConstraint) -- only nudges order *within* that layer.
  function inputOrderHint(order) {
    return secretPresent ? { 'elk.position': `(${order * 10}, 0)` } : {};
  }

  function addEdge(sourceGraphNode, targetId, targetPort) {
    const { id: srcId, port: srcPort } = outPortOf(sourceGraphNode);
    edges.push({ id: `e${nextEdge++}`, sources: [`${srcId}.${srcPort}`], targets: [`${targetId}.${targetPort}`] });
  }

  // Word w (0-based) of a multi-word call's tuple result is reached via an
  // 'index' node (see buildGraph's resolveRef fix) -- it has no ELK node
  // of its own, it just names a specific SOUTH port of its `of` node.
  function outPortOf(node) {
    if (node.kind === 'index') {
      const ofId = ensureNode(node.of);
      return { id: ofId, port: `out${node.index - 1}` };
    }
    // A declared word-group leaf (see buildGraph's own tagging from
    // parseDeclarations) shares one physical multi-word input node with
    // its sibling words -- ensureNode resolves it to that shared node's
    // id (see its own 'input'+wordGroup branch below); the specific word
    // is just a fixed port index on that shared node, exactly like a
    // multi-word call's own 'index' case above. Only when the group is
    // actually safe to share (see safeWordGroups) -- otherwise this leaf
    // is drawn as its own plain, independent input node instead, same as
    // if it had no wordGroup tag at all.
    if (node.kind === 'input' && node.wordGroup && shareableWordGroups.has(node.wordGroup.groupId)) {
      return { id: ensureNode(node), port: `out${node.wordGroup.index}` };
    }
    return { id: ensureNode(node), port: 'out' };
  }

  // `sideOutput` ('WEST'|'EAST', 'compact' strategy only): requests that
  // -- if `node` is a fresh 1-argument call, not already built via some
  // other reference -- its real output be moved to that side instead of
  // the default SOUTH (see the argCount===1 branch below). Ignored for
  // any other node shape, and for a node that's already in `idOf` (a
  // shared/reused value some other call also depends on -- forcing that
  // one sideways could break the other, unrelated use, so compact mode
  // deliberately only ever applies to a fresh, single-use node).
  function ensureNode(node, sideOutput) {
    if (idOf.has(node)) return idOf.get(node);

    // A declared word-group leaf (see buildGraph's tagging from
    // parseDeclarations) shares ONE physical multi-word input node with
    // its sibling words -- if some other word of the same group already
    // built it, just point this leaf at that node's id (no new id
    // allocated, no new child pushed); the specific word is reached via
    // outPortOf's own wordGroup case above. Only when the group is safe
    // to share (see safeWordGroups) -- an unsafe group falls through to
    // the plain single-word branch below, one independent node per word.
    if (node.kind === 'input' && node.wordGroup && shareableWordGroups.has(node.wordGroup.groupId)) {
      const { groupId, total, allIndices } = node.wordGroup;
      if (groupNodeIds.has(groupId)) {
        const sharedId = groupNodeIds.get(groupId);
        idOf.set(node, sharedId);
        return sharedId;
      }
      const order = nextId;
      const id = `n${nextId++}`;
      idOf.set(node, id);
      groupNodeIds.set(groupId, id);
      // Mirrors the multi-word CALL branch below: one out<w> port per
      // active word-slot, fixed at its own column, `width: total` so a
      // trailing spacer word-slot (an "activeWords" gap, see
      // blockCatalog.js) reserves its column with no port at all -- same
      // "no port at all" mechanics as any other spacer word.
      const ports = allIndices.map((w) => makeFixedPosPort(id, `out${w}`, w + 0.5, 1));
      children.push({
        id,
        width: total,
        height: 1,
        layoutOptions: { 'elk.portConstraints': 'FIXED_POS', 'elk.layered.layering.layerConstraint': 'FIRST', ...inputOrderHint(order) },
        ports,
      });
      meta.set(id, {
        type: 'input',
        params: {
          ...defaultParams('input'),
          words: total,
          ...(allIndices.length < total ? { activeWords: allIndices.join(',') } : {}),
          secrecy: node.groupSecret ? 'secret' : 'public',
        },
      });
      return id;
    }

    const order = nextId;
    const id = `n${nextId++}`;
    idOf.set(node, id);

    if (node.kind === 'input') {
      // Every input pinned to the first layer, regardless of how deep its
      // own consumer sits (e.g. input1 feeding a nested rotate() vs input2
      // feeding the outer call directly) -- otherwise ELK's default rank
      // assignment happily lets two equally-valid sources land on
      // different layers, which reads as "these aren't both top-level
      // inputs" even though they are.
      children.push({
        id,
        width: 1,
        height: 1,
        layoutOptions: { 'elk.portConstraints': 'FIXED_SIDE', 'elk.layered.layering.layerConstraint': 'FIRST', ...inputOrderHint(order) },
        ports: [makePort(id, 'out', 'SOUTH')],
      });
      // No explicit id here -- leave it unset so grid.placeBlock's own
      // row/col-derived fallback (defaultIdFor) applies, exactly like a
      // hand-placed input ("IN0_0", not the pseudocode name): a leaf's
      // *position* already uniquely identifies it, and the raw pseudocode
      // name (e.g. "input[1]") sanitizes to something longer than the
      // abbreviation+coordinates convention every other block type uses.
      // A word-group leaf that fell through here (its group wasn't safe
      // to share, see safeWordGroups) still needs its secrecy fact --
      // groupSecret already ORs across every declared-secret member of
      // its group, so prefer it over the leaf's own `.secret` (which only
      // reflects THIS word's own declaration line, not its siblings').
      const secret = node.wordGroup ? node.groupSecret : node.secret;
      meta.set(id, { type: 'input', params: { ...defaultParams('input'), secrecy: secret ? 'secret' : 'public' } });
      return id;
    }
    if (node.kind === 'named') {
      children.push({
        id,
        width: 1,
        height: 1,
        layoutOptions: { 'elk.portConstraints': 'FIXED_SIDE' },
        ports: [makePort(id, 'in', 'NORTH'), makePort(id, 'out', 'SOUTH')],
      });
      const sanitizedLabel = node.label.replace(/\W/g, '_');
      meta.set(id, { type: 'intermediate_output', params: { ...defaultParams('intermediate_output'), label: sanitizedLabel, id: sanitizedLabel } });
      addEdge(node.inner, id, 'in');
      return id;
    }

    // call
    const multiWord = isMultiWordType(node.typeName) && node.args.length > 1 && (node.typeName !== 'free_text' || indexedCalls.has(node));
    if (multiWord) {
      const words = node.args.length;
      const ports = [];
      for (let w = 0; w < words; w++) ports.push(makeFixedPosPort(id, `in${w}`, w + 0.5, 0));
      for (let w = 0; w < words; w++) ports.push(makeFixedPosPort(id, `out${w}`, w + 0.5, 1));
      children.push({ id, width: words, height: 1, layoutOptions: { 'elk.portConstraints': 'FIXED_POS' }, ports });
      // No operator_style override here -- see the comment on the 1-arg/
      // 2-arg branch below for why defaultParams' own 'word' is the right
      // fallback, not a hardcoded 'symbol'.
      meta.set(id, { type: node.typeName, params: { ...defaultParams(node.typeName), ...node.params, words } });
      node.args.forEach((arg, w) => addEdge(arg, id, `in${w}`));
      return id;
    }

    const argCount = node.args.length;
    // For a 2-argument call, arg0 becomes the vertical/trunk argument
    // instead of the catalog's own default (arg1). Keeping the *first*
    // textual argument as the one that continues straight down (with the
    // second arriving laterally from the east) is what makes a chain
    // rooted at a leading argument -- e.g. `xor(rotate(input1), input2)`
    // or `modadd(rotate[amount=7](input1), input2)` (Speck's own round
    // function) -- land under that argument's own column instead of
    // drifting to whichever column its *second* argument's leaf happens
    // to occupy (confirmed empirically, not just in principle: ELK's
    // coordinate assignment balances a node's *two* incoming edges
    // against each other, so which one is "the vertical one" measurably
    // changes how well the node's column matches either source).
    //
    // This is a fixed convention, not a semantically-derived choice --
    // tried replacing it with the sibling CLAASP asciiart compiler's own,
    // more principled rule for column inheritance (fewer other consumers
    // wins the vertical slot; see project history for the source
    // reference and the comparison), and it agrees with "always arg0" on
    // every case tried except one, where it *regressed* an already-
    // working corpus file with no offsetting fix -- tracing why showed
    // it wasn't that the rule was wrong, but that it steered that
    // specific case onto a *different* rough edge of this file's own
    // fan-out/routing drawing code than "always arg0" happens to avoid.
    // Kept the simpler, empirically-validated default rather than trade
    // one file's success for another's on a rule that isn't actually
    // safe against every shape this drawing code can be given yet.
    //
    // xor/and/or express the resulting port arrangement via their own
    // catalog `side` param (matching how real corpus files, e.g.
    // toy_primitives/even_mansour's key XOR, already use `side=right`);
    // every other 2-input component (modadd, modsub, ...) has no such
    // param, so the same arrangement is expressed via the generic
    // portLeft/portRight override blockCatalog.js already supports for
    // any component -- exactly how the real Speck library file's own
    // modadd block is encoded (`portLeft=off,portRight=in`), confirmed by
    // decoding it directly. Both mechanisms are read back identically by
    // gridToPseudocode's extraction (blockPorts-driven, not index-driven,
    // so it recovers the right argument order regardless of which
    // mechanism was used or which side was actually chosen).
    //
    // Not applied when flipping would make the vertical argument a
    // trivial chain topped by a leaf the *other* argument also reaches
    // (see riskyShare) -- e.g. `xor(F(input), input)`, the same `input`
    // leaf feeding both: flipping would put F's own chain directly,
    // adjacently below the fan-out point (nothing forces it any further
    // away), which collapses the fan-out group's shortest sibling path to
    // essentially nothing -- a real, separately-tracked gap in the
    // fan-out drawing logic (see project history) that this flip must not
    // go out of its way to trigger on a shape that worked before it. A
    // deep, indirect share several levels down on one side (e.g.
    // `xor(modadd(rotate(input1), input2), rotate2(input2))`, Speck's own
    // second line, where `input2` is reachable from both arguments but
    // isn't sitting right at either one's own top) isn't this risk and
    // must not block the flip -- confirmed directly: an overly broad "any
    // shared node at all" guard left Speck's own `xor` unflipped and its
    // column stranded far from both its real sources, and even the
    // precisely-scoped version of the guard still leaves that one case
    // unflipped today because flipping it hits the *separate* real crash
    // above, not because this guard blocks it. Also not applied when the
    // pseudocode already gave this instance an explicit side/port-
    // override param of its own -- respect it as-is rather than risk a
    // second, conflicting port assignment on top.
    const hasOwnPortChoice = node.params.side !== undefined || node.params.portLeft !== undefined || node.params.portRight !== undefined;
    // Flipping makes arg0 (specifically) the vertical/NORTH-fed argument
    // -- which assumes arg0's own source lands in the SAME column as this
    // call, an assumption a lateral (WEST/EAST) port doesn't need to make.
    // riskyShare only refuses the flip when arg0 shares a leaf with arg1
    // *within this same call*; it says nothing about arg0 being reused
    // *elsewhere in the whole graph*, which pulls its actual source into
    // a column of its own regardless of this call, breaking that same
    // assumption just as badly (confirmed directly: this silently
    // mis-wired lai_massey.asciiart, caught only by the later
    // checkConnectivity check, and collided immediately at draw time for
    // chacha_quarterround.asciiart). Deliberately asymmetric (only checks
    // arg0, the one the flip actually promotes) -- if arg0 itself isn't
    // reused, flipping is still safe regardless of arg1's own reuse,
    // since arg1 becomes lateral either way; if arg0 IS reused, blocking
    // the flip falls back to arg1 vertical, the same baseline every
    // strategy with canFlip already false (e.g. 'catalog-default') already
    // accepts today -- strictly reducing risk, never introducing a new one.
    // Both arguments reused (no column is ever safe) is a genuinely harder
    // case with no single right answer -- left as a known, accepted
    // residual limitation (matches computeTrunkPredOf's own "both or
    // neither reused -> silent" precedent for the same shape).
    const arg0ReusedElsewhere = argCount === 2 && trivialChainLeaf(node.args[0]) && useCount(trivialChainLeaf(node.args[0])) > 1;
    // The genuinely harder residual case both canFlip's own comment and
    // computeTrunkPredOf's "both or neither reused -> silent" precedent
    // flag as having "no single right answer": a 2-argument call where
    // BOTH arguments are reused elsewhere in the graph, each pulled toward
    // its own other usage's column -- confirmed directly (norx_quarterround's
    // `output[1] = h(temp[1], temp[2])`) these can sit on OPPOSITE sides of
    // this call (one argument's other use is far to call's the left, the
    // other's is far to the right), so EITHER vIdx choice (flip or not)
    // forces one argument's FIXED_SIDE port to face the wrong way relative
    // to where ELK actually places its source -- not a bad choice between
    // two options, a shape neither option can represent. Checked via
    // useCount directly (not trivialChainLeaf, which only follows a chain
    // down to a raw leaf) so this also catches a reused NAMED/temp value,
    // not just a reused input -- confirmed necessary: temp[1]/temp[2] are
    // both 'named' nodes, never leaves. The fix is a third port shape this
    // 2-argument call has never used before: NEITHER argument vertical,
    // both lateral (WEST + EAST), output still SOUTH -- letting ELK place
    // each argument's subtree on whichever side it naturally lands, with
    // no vertical-alignment assumption for either to violate. Extraction
    // needs no change at all: pseudocode.js's own call-reading loop
    // already derives argument order generically from blockPorts' 'in'
    // sides in a fixed ['left','top','right','bottom'] scan order, so a
    // component with portTop='off' naturally reads back as [left, right]
    // -- confirmed directly by reading that loop, not assumed. Excludes a
    // word-group member on either side (its own column is fixed by its
    // shared multi-word node -- see computeTrunkPredOf's identical
    // exclusion) and anything with its own explicit port/side choice
    // already (respect it as-is, same precedent as canFlip above).
    const isWordGroupArg = (n) => n.kind === 'input' && Boolean(n.wordGroup);
    const bothArgsReusedElsewhere =
      argCount === 2 && !hasOwnPortChoice && !isWordGroupArg(node.args[0]) && !isWordGroupArg(node.args[1]) &&
      useCount(node.args[0]) > 1 && useCount(node.args[1]) > 1;
    const canFlip =
      strategy !== 'catalog-default' && argCount === 2 && !hasOwnPortChoice && !bothArgsReusedElsewhere &&
      (relaxedFlip || (!riskyShare(node.args[0], node.args[1]) && !arg0ReusedElsewhere));
    const hasSideParam = canFlip && BLOCK_TYPES[node.typeName].params.some((p) => p.name === 'side');
    // 'successor-count': whichever argument has fewer other consumers
    // elsewhere in the graph wins the vertical slot (ties keep arg0, same
    // bias as the default strategy); 'arg0' (or anything else): always arg0.
    const vIdx = !canFlip
      ? verticalArgIndex(argCount)
      : strategy === 'successor-count'
        ? successorCountOf(node.args[0]) <= successorCountOf(node.args[1]) ? 0 : 1
        : 0;
    const ports = [];
    if (argCount === 0) {
      ports.push(makePort(id, 'out', 'SOUTH'));
    } else if (argCount === 1) {
      ports.push(makePort(id, 'in', 'NORTH'), makePort(id, 'out', sideOutput || 'SOUTH'));
    } else if (bothArgsReusedElsewhere) {
      ports.push(makePort(id, 'arg0', 'WEST'), makePort(id, 'arg1', 'EAST'), makePort(id, 'out', 'SOUTH'));
    } else {
      for (let i = 0; i < argCount; i++) {
        const side = i === vIdx ? 'NORTH' : i < vIdx ? 'WEST' : 'EAST';
        ports.push(makePort(id, `arg${i}`, side));
      }
      ports.push(makePort(id, 'out', 'SOUTH'));
    }
    // A 1-argument call chain rooted at a *shared* word-group leaf (see
    // safeWordGroups) -- directly (`sbox(input[k])`) or through further
    // 1-arg calls (`sbox(sbox(input[k]))`, trivialChainLeaf already walks
    // exactly this) -- sits under (or, for a later stage, straight below)
    // a node whose ports are packed at a 1.0-unit pitch (one per word).
    // ELK's own node-node spacing (ELK_OPTIONS above) forces >=1.0-unit
    // *gaps between node boundaries*, i.e. >=2.0 units center-to-center
    // for two such width-1 siblings -- geometrically impossible for every
    // sibling to land under its own port at once (confirmed by direct ELK
    // experiment): the coordinate assignment satisfies one and shoves the
    // rest outward, exactly the "sbox pushed left of the input/output
    // span" shape reported for double_sbox_permutation.
    // `elk.spacing.individual` overrides node-node spacing for just this
    // node's own neighbor gaps -- confirmed directly (throwaway elkjs
    // experiment, then the real double_sbox_permutation corpus file) to
    // let same-shaped siblings pack at the port pitch instead, with no
    // effect on unrelated diagrams (every other call node keeps the
    // ordinary global spacing). Deliberately scoped to only this narrow,
    // confirmed shape rather than applied broadly -- an unconditional
    // zero-spacing override would risk two genuinely unrelated
    // single-argument nodes landing in the same grid column.
    const chainLeaf = argCount === 1 ? trivialChainLeaf(node) : null;
    const argIsSharedWordGroupMember = chainLeaf && chainLeaf.wordGroup && shareableWordGroups.has(chainLeaf.wordGroup.groupId);
    const layoutOptions = { 'elk.portConstraints': 'FIXED_SIDE' };
    if (argIsSharedWordGroupMember) layoutOptions['elk.spacing.individual'] = 'elk.spacing.nodeNode: 0';
    children.push({ id, width: 1, height: 1, layoutOptions, ports });
    // operator_style is purely a display choice, dropped entirely by
    // gridToPseudocode's extraction (see pseudocode.js's own
    // OPERATOR_PARAM_NAMES comment) -- there is no way to recover the
    // original diagram's choice from pseudocode text, so this falls back
    // to whatever blockCatalog.js's own defaultParams says (currently
    // 'word' for every component), rather than hardcoding a specific
    // style here. That fallback previously hardcoded 'symbol' regardless
    // of the catalog default, which silently defeated the diagram-exact-
    // match check for every word-style component (the common case) even
    // when the rest of the layout matched byte-for-byte.
    const params = { ...defaultParams(node.typeName), ...node.params };
    if ('inputs' in params) params.inputs = argCount;
    if (bothArgsReusedElsewhere) {
      params.portTop = 'off';
      params.portLeft = 'in';
      params.portRight = 'in';
    } else if (canFlip) {
      if (hasSideParam) params.side = 'right';
      else {
        params.portLeft = 'off';
        params.portRight = 'in';
      }
    }
    if (sideOutput) {
      // 'compact' strategy only (see the call site below) -- the real
      // output moves off the default bottom/SOUTH port onto the side
      // matching where this node's own consumer expects it laterally
      // from, reusing the exact same portLeft/portRight/portBottom
      // override mechanism hand-drawn diagrams already use for this
      // (confirmed type-agnostic, no validation gap for this combination
      // -- see blockCatalog.js's componentSidePort).
      setComponentSidePort(params, 'bottom', 'off');
      setComponentSidePort(params, sideOutput === 'WEST' ? 'left' : 'right', 'out');
    }
    meta.set(id, { type: node.typeName, params });
    if (argCount === 1) addEdge(node.args[0], id, 'in');
    else if (argCount > 1) {
      node.args.forEach((arg, i) => {
        // 'compact' strategy: when this argument is lateral (not the
        // vertical/trunk one) and is itself a plain 1-argument call --
        // exactly the `F(input)` feeding `xor(other, F(input))` shape
        // every real *_compact hand-drawn example uses -- lay it out
        // sideways instead of stacking it above its consumer. The side
        // is the *opposite* of where it enters the consumer (entering the
        // consumer's WEST port means this node's own box sits to the
        // consumer's left, so its own output must face EAST to reach
        // rightward into that port, and vice versa) -- verified directly
        // against a real synthesized diagram, not just reasoned through,
        // per this file's own "don't assume port-side geometry" lesson.
        //
        // Measured, honest result: 0 dataflow mismatches across the whole
        // corpus (50/77 exact+equivalent, on par with 'arg0''s own 46/77),
        // and a real, substantial improvement on the motivating *_compact
        // files specifically (classical_feistel_compact[rounds=1]: rows
        // 9->6, blocks 28->15, turns 10->8 vs. 'arg0' -- still not
        // byte-exact against the hand-drawn original, since ELK doesn't
        // pull the sideways node directly adjacent to its consumer the
        // way a human draws it, and the interaction with
        // alignDeclaredOutputs' own output-realignment pass can still
        // pick a wider multiblockpermutation span than strictly needed on
        // some inputs -- not further tuned here, matching this file's own
        // standing caution against chasing ELK's coordinate-assignment
        // compromises via ad hoc tuning).
        if (strategy === 'compact' && i !== vIdx && arg.kind === 'call' && arg.args.length === 1) {
          ensureNode(arg, i < vIdx ? 'EAST' : 'WEST');
        }
        addEdge(arg, id, `arg${i}`);
      });
    }
    return id;
  }

  for (const t of targetOrder) {
    if (t.isOutput) {
      // A declared output word-group (see buildGraph's own tagging from
      // parseDeclarations), when safe to share (see safeWordGroups),
      // draws ONE shared multi-word output node with fixed-position
      // in<w> ports instead of each word its own 1x1 node -- mirrors the
      // input word-group branch below exactly, just NORTH-facing in<w>
      // ports instead of SOUTH-facing out<w> ones.
      if (t.wordGroup && shareableWordGroups.has(t.wordGroup.groupId)) {
        const { groupId, total, allIndices, index } = t.wordGroup;
        let id;
        if (groupNodeIds.has(groupId)) {
          id = groupNodeIds.get(groupId);
        } else {
          id = `n${nextId++}`;
          groupNodeIds.set(groupId, id);
          const ports = allIndices.map((w) => makeFixedPosPort(id, `in${w}`, w + 0.5, 0));
          children.push({
            id,
            width: total,
            height: 1,
            layoutOptions: { 'elk.portConstraints': 'FIXED_POS', 'elk.layered.layering.layerConstraint': 'LAST' },
            ports,
          });
          meta.set(id, {
            type: 'output',
            params: { ...defaultParams('output'), words: total, ...(allIndices.length < total ? { activeWords: allIndices.join(',') } : {}) },
          });
        }
        outputIdByName.set(t.name, id);
        addEdge(t.node, id, `in${index}`);
        continue;
      }

      const id = `n${nextId++}`;
      // Mirrors the input pinning above -- every output on the last
      // layer, regardless of how shallow its own source computation is.
      children.push({
        id,
        width: 1,
        height: 1,
        layoutOptions: { 'elk.portConstraints': 'FIXED_SIDE', 'elk.layered.layering.layerConstraint': 'LAST' },
        ports: [makePort(id, 'in', 'NORTH')],
      });
      // Same as the input leaves above -- no explicit id, so the
      // row/col-derived fallback applies ("OU10_11", not the declared
      // target name, which is available already via gridToPseudocode's
      // own extraction and would otherwise run well past the
      // abbreviation+coordinates convention's length for a longer target
      // name like "leftHalf").
      meta.set(id, { type: 'output', params: defaultParams('output') });
      outputIdByName.set(t.name, id);
      addEdge(t.node, id, 'in');
    } else {
      ensureNode(t.node);
    }
  }

  return { graph: { id: 'root', layoutOptions: ELK_OPTIONS, children, edges }, meta, idOf, outputIdByName };
}

// ------------------------------------------------------------ draw pass --

// ELK's coordinate assignment does not produce exact integer gaps between
// layers/columns (confirmed empirically: a nominal 1-unit gap comes back
// as e.g. 1.02, and drifts further with every additional layer -- by
// layer 50 the cumulative drift exceeds 1 unit, enough to misplace a naive
// `floor(y / unit)` by a whole row). Absolute magnitude is not
// trustworthy, so this classifies every coordinate against the *known*
// node bands instead (each node is exactly 1 unit wide/tall in ELK's own
// coordinate space -- reliably so, only tiny float noise, ~0.01-0.02).
//
// A coordinate can fall in one of two places: inside some node's own
// 1-unit band (not just exactly at its corner -- e.g. a WEST-port corner
// sitting at a node's vertical center is still "that node's row"), or in
// the *gap* between two consecutive bands, which is only sometimes wide
// enough -- or actually used -- for a routing jog into a port-constrained
// neighbor (see this file's own history: with a zero-width gap there is
// no room to jog sideways before entering a NORTH/SOUTH-only port from a
// different column). A gap only becomes its own row/column index when
// some edge's own point genuinely falls inside it, so a plain, no-jog
// direct chain never gets a spurious empty row.
const SNAP_EPS = 0.05;
const BAND = 1; // every node is exactly 1 unit wide/tall in ELK's own coordinate space

// Two nodes ELK intends to share a column/row don't always come back
// bit-identical -- e.g. two independent near-zero coordinates can land at
// 4.3e-18 and 8.7e-18, both "0" for any practical purpose but distinct as
// JS numbers. A plain `Set` treats those as separate bands, which doesn't
// just waste a column: `classify` below matches the *first* band a value
// falls within, so every one of these near-duplicate phantom bands still
// occupies its own slot in `bandStarts`, artificially inflating the index
// (and therefore the rendered gap) of every *real* band that sorts after
// them. Clustering by a tolerance well below any genuine inter-node
// spacing (ELK nodes are never closer than ~1 unit apart) but well above
// float noise (~1e-15 scale) collapses these before they can do that.
// Reuses SNAP_EPS's own already-established tolerance rather than a
// separate, tighter magic number -- confirmed necessary, not just
// generous margin: `elk.spacing.individual` overrides (see buildElkGraph)
// don't always collapse a sibling's own coordinate to bit-identical
// either, sometimes leaving a small (~0.005) but genuine, deterministic
// offset -- comfortably below any real inter-node spacing (~1 unit) but
// well above the old 1e-6, which classified it as its own phantom band.
const BAND_DEDUPE_EPS = SNAP_EPS;
// Lane-clustering tolerance for gap values -- see buildAxisIndex's own
// lane-aware gap indexing comment for the full rationale and the measured
// bounds it sits between (same-lane float noise far below, real ELK lane
// separation far above).
const LANE_EPS = 0.5;

function buildAxisIndex(nodeValues, allValues) {
  const sortedNodeValues = [...nodeValues].sort((a, b) => a - b);
  const bandStarts = sortedNodeValues.filter((v, i) => i === 0 || v - sortedNodeValues[i - 1] > BAND_DEDUPE_EPS);

  function classify(v) {
    for (let i = 0; i < bandStarts.length; i++) {
      if (v >= bandStarts[i] - SNAP_EPS && v < bandStarts[i] + BAND - SNAP_EPS) return { band: i };
    }
    // A long-distance route (e.g. a multi-round diagram's back-edge) can
    // loop out to a column/row *before* the first band entirely, not just
    // between two known ones -- represented as gap "-1" (before band 0),
    // handled the same way as an ordinary inter-band gap below.
    if (v < bandStarts[0] - SNAP_EPS) return { gapAfter: -1 };
    for (let i = 0; i < bandStarts.length - 1; i++) {
      if (v >= bandStarts[i] + BAND - SNAP_EPS && v < bandStarts[i + 1] - SNAP_EPS) return { gapAfter: i };
    }
    // Symmetric case: a route can just as well loop out *past* the last
    // band as before the first one -- confirmed by direct construction,
    // not guessed: a lateral argument's own east-side excursion, in a
    // graph where every real node happens to share one column (e.g.
    // `xor(F(input), input)` once `F(input)` is vertical, leaving `input`
    // itself as the only thing that needs to reach sideways), has nowhere
    // else to land. The previous behavior here -- silently clamping into
    // the last band instead of giving this its own gap -- collapsed that
    // excursion into the same column as everything else, producing
    // unroutable overlapping cells with no genuine bug in the drawing
    // code to blame; this is the fix, not a drawing-side workaround.
    return { gapAfter: bandStarts.length - 1 };
  }

  // Lane-aware gap indexing: ELK routes parallel edges through the same
  // inter-band gap as DISTINCT lanes (its own edge-edge spacing keeps them
  // ~1.5-10 units apart in raw coordinates -- confirmed by direct
  // instrumentation on the failing corpus files: chacha[rounds=2] alone had
  // 25 gaps each carrying 2-4 lanes, and ascon_nonlinear_layer's failure
  // row was 4 lanes at y=1,11,21,31 all collapsed together). Mapping every
  // value in a gap to ONE index (the previous behavior) threw that
  // separation away and forced unrelated wires into the same grid cell --
  // the confirmed root cause of the "two wires can't be drawn as a single
  // crossing block" / "a third wire can't share a cell" failures. Each gap
  // now gets one grid index PER coordinate cluster ("lane") instead: values
  // within LANE_EPS of each other (chained) share a lane; a gap whose
  // values all sit in one lane -- the common case -- indexes exactly as
  // before, so plain diagrams are byte-identical to the old behavior.
  //
  // LANE_EPS is lane-spacing scale, deliberately NOT SNAP_EPS/
  // BAND_DEDUPE_EPS (float-noise scale, see above -- reusing those here
  // would resurrect the phantom-band bug they exist to kill in the other
  // direction): well above same-lane float noise (~0.01-0.02) and below
  // the smallest genuinely-distinct lane separation observed on the real
  // corpus (~1.5 units).
  const gapLanes = new Map(); // gapAfter -> [{ min, max }] ascending
  for (const v of allValues) {
    const c = classify(v);
    if (c.gapAfter === undefined) continue;
    if (!gapLanes.has(c.gapAfter)) gapLanes.set(c.gapAfter, []);
    gapLanes.get(c.gapAfter).push(v);
  }
  for (const [g, vals] of gapLanes) {
    vals.sort((a, b) => a - b);
    const lanes = [];
    for (const v of vals) {
      if (!lanes.length || v - lanes[lanes.length - 1].max > LANE_EPS) lanes.push({ min: v, max: v });
      else lanes[lanes.length - 1].max = v;
    }
    gapLanes.set(g, lanes);
  }
  const sortedGaps = [...gapLanes.keys()].sort((a, b) => a - b);
  const lanesBefore = (bandIdx) => sortedGaps.filter((g) => g < bandIdx).reduce((n, g) => n + gapLanes.get(g).length, 0);
  const indexOfBand = bandStarts.map((_, i) => i + lanesBefore(i));
  const gapBaseIndex = new Map(sortedGaps.map((g) => [g, g === -1 ? 0 : indexOfBand[g] + 1]));

  return (v) => {
    const c = classify(v);
    if (c.band !== undefined) return indexOfBand[c.band];
    const lanes = gapLanes.get(c.gapAfter);
    const base = gapBaseIndex.get(c.gapAfter);
    for (let i = 0; i < lanes.length; i++) {
      if (v <= lanes[i].max + LANE_EPS) return base + i;
    }
    return base + lanes.length - 1; // defensive -- every classified gap value was clustered above
  };
}

function pointsOf(edge) {
  const pts = [];
  for (const sec of edge.sections || []) {
    pts.push(sec.startPoint, ...(sec.bendPoints || []), sec.endPoint);
  }
  return pts;
}

// No 'bottom,left'/'bottom,right' entries -- every route this file ever
// draws flows downward (matches REWIRE_PORTS's own no-bottom-in-port rule),
// so a turn entering from the bottom should never actually occur; if one
// somehow did, this correctly falls through to drawRouteCell's "Unroutable
// turn" error instead of silently placing an upside-down wire block.
const REWIRE_DIRECTION = Object.fromEntries(
  Object.entries(REWIRE_PORTS).map(([variant, ports]) => {
    const entry = Object.keys(ports).find((side) => ports[side] === 'in');
    const exit = Object.keys(ports).find((side) => ports[side] === 'out');
    return [`${entry},${exit}`, variant];
  })
);

function sideBetween(fromCell, toCell) {
  // Which side of `fromCell` faces `toCell` (its immediate grid neighbor).
  // Each check requires the *other* coordinate to match too -- without
  // that, a genuinely diagonal (non-adjacent) pair silently matches the
  // first row-only or column-only condition instead of falling through to
  // the error below (confirmed to happen: a caller that ever builds a
  // non-axis-aligned waypoint list gets a wrong cardinal direction back,
  // not a clear failure).
  const [r1, c1] = fromCell;
  const [r2, c2] = toCell;
  if (r2 === r1 - 1 && c2 === c1) return 'top';
  if (r2 === r1 + 1 && c2 === c1) return 'bottom';
  if (c2 === c1 - 1 && r2 === r1) return 'left';
  if (c2 === c1 + 1 && r2 === r1) return 'right';
  throw new Error(`Non-adjacent cells in a routed path: [${r1},${c1}] -> [${r2},${c2}]`);
}

// Recovers the single (entry,exit) route a plain `wire` block at a cell
// represents -- used to detect when a *different*, unrelated path's own
// route through that same cell is a genuine crossing rather than a
// duplicate of the same route (a shared fan-out prefix, which is handled
// separately -- see drawInterior). Returns null for anything that isn't a
// single-route block (a `double_wire` is already full).
function sidesOf(type, params) {
  if (type === 'wire') {
    const [entry, exit] = params.direction.split('_to_');
    return { entry, exit };
  }
  return null;
}

// Two independent routes crossing the same cell without connecting need
// `double_wire`, which covers exactly 4 pairings: both routes straight
// through, like a "+" (formerly its own `cross` type), or both routes
// turning, drawn with a diagonal offset since neither passes straight
// through the centre (see blockCatalog.js's own comment on why that offset
// is needed). Returns null if this specific pair of routes isn't one of
// those 4 (overlapping sides, three-plus routes, or a straight route paired
// with a turning one -- there's no catalog block for that shape).
function mergedCrossBlock(a, b) {
  const sides = new Set([a.entry, a.exit, b.entry, b.exit]);
  if (sides.size !== 4) return null; // overlapping sides -- not a clean crossing
  const isStraight = (r) => OPPOSITE[r.entry] === r.exit;
  if (isStraight(a) && isStraight(b)) {
    // double_wire's straight+straight variants only support a top-to-bottom
    // vertical flow (never bottom-to-top) -- matches how every route in
    // this file already flows, so this should always hold in practice; bail
    // out rather than silently mis-drawing if it somehow doesn't.
    const vertical = a.entry === 'top' || a.entry === 'bottom' ? a : b;
    const horizontal = vertical === a ? b : a;
    if (vertical.entry !== 'top' || vertical.exit !== 'bottom') return null;
    const variant = horizontal.entry === 'right' ? 'top_to_bottom+right_to_left' : 'top_to_bottom+left_to_right';
    return { type: 'double_wire', params: { variant, label: 'round' } };
  }
  if (isStraight(a) || isStraight(b)) return null; // one straight + one turning -- no catalog block for this
  const key = (r) => `${r.entry}_to_${r.exit}`;
  const pair = new Set([key(a), key(b)]);
  if (pair.has('top_to_left') && pair.has('right_to_bottom')) {
    return { type: 'double_wire', params: { variant: 'top_to_left+right_to_bottom', label: 'round' } };
  }
  if (pair.has('top_to_right') && pair.has('left_to_bottom')) {
    return { type: 'double_wire', params: { variant: 'top_to_right+left_to_bottom', label: 'round' } };
  }
  return null; // a turn pair/polarity double_wire's turning variants don't cover
}

// Converts one edge's full point list -- its true endpoints (the already-
// known source/target node cells, see layoutToGrid, NOT re-derived from
// raw coordinates -- an edge's own start/end point can land fractionally
// off its node's true row/column boundary) plus any genuinely
// intermediate bend points (classified via the axis indices) -- into the
// full, gap-free sequence of grid cells it passes through: every segment
// walked one cell at a time, so a long horizontal/vertical run yields one
// entry per cell, not just its two endpoints.
//
// Every consecutive pair here is expected to already share a row or a
// column (a genuinely orthogonal-routed edge never needs to move both at
// once) -- except at specific seams where axis classification (see
// buildAxisIndex) or our own synthetic `forcedFirstStep` waypoint (see
// layoutToGrid) can land two adjacent raw points off-axis from each
// other. Confirmed by direct construction, twice: once between
// `forcedFirstStep` and an edge's own first real bend (a 2-argument
// call's lateral argument reaching it from the side opposite its trunk
// chain, a shape the vertical-argument flip above can create), and once
// between two of an edge's own later bend points (Speck's own `xor`,
// once *it* is also flipped) -- so this isn't a one-seam special case,
// it's inherent to combining ELK's own bend points with cell indices
// classified independently per axis.
//
// Bending such a pair needs an explicit corner -- either horizontal-then-
// vertical ([r1,c2]) or vertical-then-horizontal ([r2,c1]) -- and *both*
// are geometrically valid in isolation, but only one of them can be safe
// once there's a run already in progress: if the path most recently
// moved horizontally in one direction, bending horizontal-first here
// again, in the *opposite* direction, walks back over cells that same
// run just covered -- a genuine backtrack (confirmed by direct
// construction: `entry=left exit=left` at a cell visited twice from the
// same side, immediately followed by leaving that side again), not a
// bend a "turn" block can represent. Preferring vertical-first exactly
// when that specific reversal would happen sidesteps it: the horizontal
// leg then happens on a fresh row the earlier run never touched.
function withOrthogonalCorners(points) {
  const out = [points[0]];
  for (let i = 1; i < points.length; i++) {
    const [r1, c1] = out[out.length - 1];
    const [r2, c2] = points[i];
    if (r1 !== r2 && c1 !== c2) {
      const priorRow = out.length >= 2 ? out[out.length - 2] : null;
      const priorHorizontalDir = priorRow && priorRow[0] === r1 ? Math.sign(c1 - priorRow[1]) : 0;
      const neededDir = Math.sign(c2 - c1);
      const wouldReverse = priorHorizontalDir !== 0 && neededDir !== 0 && priorHorizontalDir !== neededDir;
      out.push(wouldReverse ? [r2, c1] : [r1, c2]);
    }
    out.push(points[i]);
  }
  return out;
}

function cellsAlong(rawPoints) {
  const points = withOrthogonalCorners(rawPoints);
  const cells = [points[0]];
  for (let i = 0; i + 1 < points.length; i++) {
    let [r, c] = points[i];
    const [r2, c2] = points[i + 1];
    while (r !== r2 || c !== c2) {
      r += Math.sign(r2 - r);
      c += Math.sign(c2 - c);
      cells.push([r, c]);
    }
  }
  return collapseBacktracks(cells);
}

// ELK's own bend points live in continuous space and can legitimately
// detour around an obstacle there; quantizing them onto this project's
// coarse discrete grid occasionally collapses that detour into a
// pointless "there and back" loop that revisits a cell it already
// passed through (confirmed directly on ascon_nonlinear_layer and
// type3_feistel[rounds=1]: a bend sequence like x=16->x=16->x=19->x=18
// quantizes into a path that walks through some column, overshoots, then
// backtracks through it again). Mid-path cells are pure routing
// waypoints, never real ports, so collapsing a revisit back to its first
// occurrence is always a safe simplification -- it can only straighten
// the path, never break start/end connectivity. Left unfixed, the
// doubled-back cell can land squarely on an unrelated already-placed
// node, which drawRouteCell has no way to draw over.
function collapseBacktracks(cells) {
  const indexOf = new Map();
  const result = [];
  for (const cell of cells) {
    const key = cellKey(cell);
    if (indexOf.has(key)) {
      const idx = indexOf.get(key);
      for (let k = idx + 1; k < result.length; k++) indexOf.delete(cellKey(result[k]));
      result.length = idx + 1;
      continue;
    }
    indexOf.set(key, result.length);
    result.push(cell);
  }
  return result;
}

function cellKey([r, c]) {
  return Grid.key(r, c);
}

// ELK's orthogonal router legitimately routes an edge UP and back over an
// obstacle in continuous space ("up-and-over hairpin"). Before lane-aware
// gap indexing (see buildAxisIndex), the hairpin's two vertical legs
// usually quantized into the SAME grid column and collapseBacktracks
// self-cancelled the excursion; with lanes split they land in adjacent
// distinct columns and the ascending leg survives -- but this project's
// wire vocabulary is strictly downward (REWIRE_DIRECTION has no
// entry='bottom'/exit='top'), so ANY interior ascent is guaranteed to
// throw "Unroutable turn" later. Rewrite each hairpin locally: from the
// cell where the ascent starts, route laterally along that same row to
// the column where the path first returns to that row (or below), then
// straight down -- i.e. re-merge the two lanes for this one edge, the
// exact inverse of the lane split, applied only where the path is
// otherwise undrawable (a path with no ascent is returned untouched, so
// this is a strict no-op for every previously-drawable route). If the
// path never comes back down (it genuinely ends above the hairpin start
// -- an upward edge, which the DAG layering shouldn't produce), it's
// returned unchanged and fails later exactly as before, rather than
// half-rewritten. The trailing collapseBacktracks removes any revisits
// the lateral shortcut introduces over cells the path already covered.
function straightenAscents(cells) {
  let hasAscent = false;
  for (let i = 0; i + 1 < cells.length; i++) {
    if (cells[i + 1][0] < cells[i][0]) { hasAscent = true; break; }
  }
  if (!hasAscent) return cells;

  // Terminal ascent ("down-and-under"): the route dives BELOW its target
  // and rises into it from underneath -- ELK's way of approaching a NORTH
  // port around a wide obstacle. A downward-only vocabulary can never draw
  // that final rising leg, but these paths reliably pass through the
  // target's own column ABOVE the target earlier on (confirmed directly on
  // xoodoo_theta: the second cell of an 89-cell loop sits immediately
  // above the target) -- truncate there and descend straight in. Only
  // attempted when the last step actually rises; if no such earlier cell
  // exists the path is left as-is (fails exactly as before).
  let work = cells;
  const [tr, tc] = work[work.length - 1];
  if (work.length >= 2 && work[work.length - 2][0] > tr) {
    for (let j = 0; j < work.length - 1; j++) {
      const [r, c] = work[j];
      if (c === tc && r < tr) {
        const rebuilt = work.slice(0, j + 1);
        for (let rr = r + 1; rr <= tr; rr++) rebuilt.push([rr, tc]);
        work = rebuilt;
        break;
      }
    }
  }

  const out = [work[0]];
  let i = 0;
  while (i + 1 < work.length) {
    if (work[i + 1][0] >= work[i][0]) {
      i++;
      out.push(work[i]);
      continue;
    }
    const [rs, cs] = work[i]; // hairpin starts here -- next cell is above
    let k = i + 1;
    while (k < work.length && work[k][0] < rs) k++;
    if (k >= work.length) return work; // never returns to this row -- leave untouched (fails as before)
    const [rk, ck] = work[k];
    let c = cs;
    while (c !== ck) {
      c += Math.sign(ck - c);
      out.push([rs, c]);
    }
    for (let r = rs + 1; r <= rk; r++) out.push([r, ck]);
    i = k;
  }
  return collapseBacktracks(out);
}

// Draws a single routing cell for one wire passing through with the given
// entry/exit sides. Collision handling reads the grid directly (not a
// separate "already visited" set) so it can tell apart two very different
// situations at an already-occupied cell: the *same* route revisited (a
// shared fan-out prefix drawn once by an earlier sibling -- a no-op here)
// versus a genuinely different, unrelated route crossing through it
// (upgraded to `double_wire` via mergedCrossBlock, or a clear error if it
// can't represent it). Shared by drawInterior (ELK-routed
// edges) and alignDeclaredOutputs (the synthetic last-row realignment
// pass, below) -- both need the exact same "what belongs in this cell"
// and "can two routes share it" logic.
// Whether drawRouteCell could draw (row,col) as `entry`/`exit` given
// whatever already sits there, without throwing -- the exact same
// no-op/mergeable/collision conditions drawRouteCell itself checks, pulled
// out so drawInterior can decide *before* drawing whether this cell needs
// a live detour first (see below). Not used by drawRouteCell itself, to
// keep that function's own error messages naming the specific collision.
function canDrawRouteCell(existing, entry, exit) {
  const existingSides = sidesOf(existing.type, existing.params);
  if (existingSides && existingSides.entry === entry && existingSides.exit === exit) return true; // same route
  if (!existingSides) return false; // an already-merged crossing, or any real (non-wire) block
  return Boolean(mergedCrossBlock(existingSides, { entry, exit }));
}

function drawRouteCell(grid, row, col, entry, exit, ctx) {
  const existing = grid.getBlockAt(row, col);
  if (existing) {
    const existingSides = sidesOf(existing.type, existing.params);
    if (existingSides && existingSides.entry === entry && existingSides.exit === exit) return; // same route, already drawn
    if (!existingSides) {
      throw new Error(`Routing collision at [${row},${col}]: a third wire can't share a cell already carrying a crossing.`);
    }
    const merged = mergedCrossBlock(existingSides, { entry, exit });
    if (!merged) {
      throw new Error(
        `Routing collision at [${row},${col}]: two unrelated wires (entry=${existingSides.entry}/exit=${existingSides.exit} and entry=${entry}/exit=${exit}) can't be drawn as a single crossing block.`
      );
    }
    grid.removeBlock(row, col);
    grid.placeBlock(row, col, merged.type, merged.params);
    return;
  }

  const direction = REWIRE_DIRECTION[`${entry},${exit}`];
  if (!direction) throw new Error(`Unroutable turn at [${row},${col}]: entry=${entry} exit=${exit}`);
  grid.placeBlock(row, col, 'wire', { borders: 'invisible', label: 'round', direction });
  // First owner wins (a later merge into double_wire keeps the original
  // owner as the negotiation blocker id -- see layoutToGrid's reorder loop).
  if (ctx?.owners && !ctx.owners.has(`${row},${col}`)) ctx.owners.set(`${row},${col}`, ctx.groupRef);
}

// Draws the routing cells strictly between a path's first cell (the
// source node's own cell, already placed) and last cell (the destination
// node's own cell, already placed) -- `cells[0]` and `cells[cells.length-1]`
// are never touched here.
function drawInterior(cells, grid, ctx) {
  let i = 1;
  while (i < cells.length - 1) {
    // sideBetween(current, previous) already IS the side the wire enters
    // through (previous sits in whichever direction that side faces) --
    // no OPPOSITE needed (unlike `exit`, which is the same function
    // applied forward, this one is naturally "backward-looking" already).
    const entry = sideBetween(cells[i], cells[i - 1]);
    const exit = sideBetween(cells[i], cells[i + 1]);
    const [row, col] = cells[i];
    const existing = grid.getBlockAt(row, col);
    // A plain ELK-node obstacle is already dodged ahead of time (see
    // avoidNodeObstacles, called from computeCellsWith before any drawing
    // happens) -- but a block an EARLIER-drawn fan-out group placed
    // dynamically (a `split`/`double_wire` junction from its own routing,
    // not one of ELK's own nodes) can't be known about that early, since
    // groups are drawn strictly one after another (see layoutToGrid).
    // Confirmed directly on ascon_nonlinear_layer: an unrelated group's
    // own `split` block ends up sitting exactly on a *later* group's
    // straight-through path, which the static occupied-set check never
    // sees coming. Same "notch" detour as avoidNodeObstacles, just decided
    // against the live grid, right before this specific cell would
    // otherwise fail to draw.
    if (existing && !canDrawRouteCell(existing, entry, exit) &&
        detourAroundObstacle(cells, i, (r, c) => r >= 0 && c >= 0 && !grid.getBlockAt(r, c))) {
      continue; // re-derive entry/exit for the newly-spliced first detour cell
    }
    drawRouteCell(grid, row, col, entry, exit, ctx);
    i++;
  }
}

// Last-resort rerouting for a single path whose pre-validated cells hit an
// unmergeable collision against the live grid: BFS over free (or
// merge-compatible) cells, restricted to the exact same downward-only turn
// vocabulary drawRouteCell enforces (moves: left/right/bottom; a state is
// (cell, entry side); a step is legal only if REWIRE_DIRECTION accepts the
// (entry, exit) pair AND the cell itself is empty or canDrawRouteCell
// accepts the crossing). Runs BEFORE anything of this path is drawn, so a
// failed search changes nothing (the original path is drawn and throws
// exactly as before) -- this can only ever activate where drawing was
// already guaranteed to fail, never on a previously-working route.
//
// Confirmed motivating shape (norx_quarterround): a WEST-port approach
// corridor quantized onto the target's own row east of the target -- no
// local notch can fix that (reaching a west port from the east at the
// target's row needs an upward move somewhere), but a genuinely different
// route over the free cells above usually exists.
const REROUTE_MOVES = { left: [0, -1], right: [0, 1], bottom: [1, 0] };
// Cost bounds: reroute only ever runs on a path that is otherwise
// guaranteed to fail, but a huge diagram can have MANY such paths x MANY
// anchors -- cap both the per-search state count and how many anchors are
// retried so a hopeless file fails in milliseconds, not minutes.
const REROUTE_STATE_CAP = 4000;
const REROUTE_MAX_ANCHORS = 6;
// Negotiated-drawing rounds (see layoutToGrid): each round is a full,
// cheap grid redraw with a reordered group sequence -- 20 matches the
// established backstop convention (planPlacement/compactColumns).
const RIPUP_MAX_ROUNDS = 20;
// Make-room retries around a failed negotiation (see layoutToGrid) --
// each inserts one empty row at the last conflict and re-derives every
// cell path from the patched row index.
const DRAW_BUFFER_MAX = 6;

// Every divergence cell any group will need for a split/junction, found
// pre-draw with the same recursive partition walk drawFanoutGroup uses --
// a corridor drawn EARLIER through one of these cells would make the later
// split placement impossible (a split can't share its cell with anything),
// an order-dependent congestion confirmed directly on norx_quarterround
// ([18,4]). Foreign groups' reserved cells are treated as blocked during
// pre-validation and rerouting; a group's own divergences stay usable.
function collectDivergenceCells(groups) {
  const reserved = new Map(); // cellKey -> owning group ref
  function walk(paths, ref) {
    if (paths.length < 2) return;
    const prefixLen = commonPrefixLen(paths);
    reserved.set(cellKey(paths[0][prefixLen - 1]), ref);
    const byNext = new Map();
    for (const p of paths) {
      if (p.length <= prefixLen) continue;
      const k = cellKey(p[prefixLen]);
      if (!byNext.has(k)) byNext.set(k, []);
      byNext.get(k).push(p.slice(prefixLen - 1));
    }
    for (const b of byNext.values()) walk(b, ref);
  }
  for (const [ref, paths] of groups) walk(paths, ref);
  return reserved;
}

// Every path's final approach cell (the forcedLastStep cell -- always
// genuinely used: even a BFS reroute must arrive through it, since the
// goal condition steps from it onto the target). A FOREIGN route may
// cross it only with the straight pass perpendicular to the feed (which
// merges into a double_wire with the feed); a foreign TURN there can
// never merge with the feed and is guaranteed to collide later -- so
// pre-validation treats it as a conflict immediately, while any crossing
// that is legal today stays legal (passing files are unaffected by
// construction). feed: 'vertical' (NORTH ports) or 'horizontal' (WEST/EAST).
function collectApproachCells(groups) {
  const approach = new Map(); // cellKey -> { group, feed }
  for (const [ref, paths] of groups) {
    for (const p of paths) {
      if (p.length < 3) continue; // approach would be the source node cell itself
      const app = p[p.length - 2];
      const exit = sideBetween(app, p[p.length - 1]);
      const feed = exit === 'bottom' ? 'vertical' : exit === 'left' || exit === 'right' ? 'horizontal' : null;
      if (feed && !approach.has(cellKey(app))) approach.set(cellKey(app), { group: ref, feed });
    }
  }
  return approach;
}

function crossesApproachIllegally(app, groupRef, entry, exit) {
  if (!app || app.group === groupRef) return false;
  if (app.feed === 'vertical') return !((entry === 'left' && exit === 'right') || (entry === 'right' && exit === 'left'));
  return !(entry === 'top' && exit === 'bottom');
}

function rerouteSegment(grid, anchor, anchorEntry, approachExit, target, bounds, blocked) {
  // Goal: reach `approach` = the cell adjacent to `target` opposite
  // approachExit... expressed directly: reach any state (cell, entry)
  // where stepping `approachExit` from `cell` lands exactly on `target`
  // and (entry, approachExit) is a drawable pair at `cell`.
  const startKey = `${anchor[0]},${anchor[1]},${anchorEntry}`;
  const seen = new Set([startKey]);
  const queue = [{ r: anchor[0], c: anchor[1], entry: anchorEntry, prev: null }];
  let qi = 0;
  while (qi < queue.length && queue.length < REROUTE_STATE_CAP) {
    const cur = queue[qi++];
    for (const exit of ['bottom', 'left', 'right']) {
      if (!REWIRE_DIRECTION[`${cur.entry},${exit}`]) continue;
      // the current cell must be drawable as (entry, exit) -- except the
      // anchor itself, which is already drawn/placed and only fixes the
      // direction we leave it in (its own glyph is not redrawn here).
      if (!(cur.prev === null)) {
        const existing = grid.getBlockAt(cur.r, cur.c);
        if (existing && !canDrawRouteCell(existing, cur.entry, exit)) continue;
      }
      const [dr, dc] = REROUTE_MOVES[exit];
      const nr = cur.r + dr;
      const nc = cur.c + dc;
      if (nr === target[0] && nc === target[1]) {
        // arrived -- but only via the required approach side
        if (exit !== approachExit) continue;
        const path = [];
        for (let s = cur; s; s = s.prev) path.push([s.r, s.c]);
        path.reverse();
        path.push([target[0], target[1]]);
        return path;
      }
      if (nr < bounds.minRow || nr > bounds.maxRow || nc < bounds.minCol || nc > bounds.maxCol) continue;
      if (blocked && blocked(nr, nc)) continue; // another group's future split cell
      const nEntry = OPPOSITE[exit];
      const k = `${nr},${nc},${nEntry}`;
      if (seen.has(k)) continue;
      const existing = grid.getBlockAt(nr, nc);
      if (existing && sidesOf(existing.type, existing.params) === null) continue; // a real block -- never enterable
      seen.add(k);
      queue.push({ r: nr, c: nc, entry: nEntry, prev: cur });
    }
  }
  return null;
}

// Draws one full single-sibling path, pre-validating every interior cell
// against the live grid first; on an unmergeable collision, attempts one
// whole-segment reroute (see rerouteSegment) from the last good cell to
// the path's own target, keeping the original error behavior when no
// reroute exists.
function drawPathWithReroute(path, grid, ctx) {
  const foreignReserved = (r, c) => {
    if (!ctx) return false;
    const owner = ctx.reserved.get(`${r},${c}`);
    if (owner !== undefined && owner !== ctx.groupRef) return true;
    const app = ctx.approach?.get(`${r},${c}`);
    return Boolean(app && app.group !== ctx.groupRef);
  };
  let firstBad = -1;
  for (let i = 1; i < path.length - 1; i++) {
    const entry = sideBetween(path[i], path[i - 1]);
    const exit = sideBetween(path[i], path[i + 1]);
    const existing = grid.getBlockAt(path[i][0], path[i][1]);
    if (foreignReserved(path[i][0], path[i][1])) { firstBad = i; break; }
    if (ctx?.approach && i !== path.length - 2 && crossesApproachIllegally(ctx.approach.get(`${path[i][0]},${path[i][1]}`), ctx.groupRef, entry, exit)) { firstBad = i; break; }
    if (existing && !canDrawRouteCell(existing, entry, exit)) { firstBad = i; break; }
    if (!existing && !REWIRE_DIRECTION[`${entry},${exit}`]) { firstBad = i; break; }
  }
  if (firstBad >= 2 && path.length >= 2) {
    const target = path[path.length - 1];
    const approachExit = sideBetween(path[path.length - 2], target);
    const { rows, cols } = grid.dimensions();
    const bounds = { minRow: 0, maxRow: rows + 1, minCol: 0, maxCol: cols + 1 };
    // The conflict cell is often unavoidable from right next to it (the
    // downward-only move set can't climb back out of a doomed corridor) --
    // retry from progressively earlier anchors so the search may leave
    // the corridor before it commits (confirmed necessary on
    // norx_quarterround: the viable route branches off several cells
    // upstream of the collision).
    // Sample anchors evenly back along the path (nearest-first) instead of
    // trying every cell -- the viable branch-off is usually within a few
    // cells or at a structurally earlier corner, and unbounded retries made
    // hopeless giant files take minutes to fail.
    const anchorIdxs = [];
    const step = Math.max(1, Math.floor((firstBad - 1) / REROUTE_MAX_ANCHORS));
    for (let a = firstBad - 1; a >= 1 && anchorIdxs.length < REROUTE_MAX_ANCHORS; a -= step) anchorIdxs.push(a);
    for (const a of anchorIdxs) {
      const anchor = path[a];
      const anchorEntry = sideBetween(anchor, path[a - 1]);
      const rerouted = rerouteSegment(grid, anchor, anchorEntry, approachExit, target, bounds, foreignReserved);
      if (rerouted) {
        drawInterior([...path.slice(0, a), ...rerouted], grid, ctx);
        return;
      }
    }
  }
  drawInterior(path, grid, ctx); // no conflict, or no reroute found -- original behavior (including its error)
}

// Longest common prefix (as a cell count, not an index) across every
// sibling path in a fan-out group -- how far all of them agree on the
// exact same cell before diverging. Shared by drawFanoutGroup and by
// findAdjacentFanoutConflict (see layoutToGrid), which needs to know this
// *before* any drawing happens, to detect a shape neither can safely draw
// (see that function's own comment).
function commonPrefixLen(paths) {
  let prefixLen = 1;
  outer: for (; ; prefixLen++) {
    const candidate = paths[0][prefixLen];
    if (!candidate) break;
    for (const p of paths) {
      const c = p[prefixLen];
      if (!c || c[0] !== candidate[0] || c[1] !== candidate[1]) break outer;
    }
  }
  return prefixLen;
}

// Fan-out (2+ edges leaving the same source port) needs an explicit
// `split` block at the point of divergence -- ELK's own `junctionPoints`
// field is not reliable for this (confirmed: edges sharing a source port
// do not reliably get one, a known upstream issue), so divergence is
// found by comparing sibling paths' own cell sequences directly. Handles
// 3+-way fan-out as a chain of splits (mirrors the pre-existing `split`
// block's own "peel off one tap, continue down to the next" shape).
function drawFanoutGroup(paths, grid, drawn, ctx) {
  if (paths.length === 1) {
    // Single-sibling path: the one place whole-segment rerouting is safe
    // (no other sibling shares cells with this suffix, so rewriting it
    // can't desynchronize a divergence another path still expects).
    drawPathWithReroute(paths[0], grid, ctx);
    return;
  }
  const prefixLen = commonPrefixLen(paths);
  // Draw the shared prefix as ordinary straight-through cells up to (but
  // not including) the divergence cell itself.
  drawInterior(paths[0].slice(0, prefixLen), grid, ctx);

  const divergeCell = paths[0][prefixLen - 1];
  const divergeKey = cellKey(divergeCell);
  if (drawn.has(divergeKey)) {
    // Another sibling group already resolved this exact divergence (can
    // happen when two different fan-out groups' prefixes overlap through
    // a shared intermediate routing cell) -- recurse into the remaining
    // suffixes AS BUNDLES, partitioned by their next cell: recursing per
    // sibling (each wrapped alone, the previous behavior here) silently
    // throws away a FURTHER shared divergence several siblings can still
    // have past this cell -- the exact mistake the straight-through case
    // below already documents (gimli_bitsliced_sbox/ascon_linear_layer).
    // Naive whole-bundle recursion would loop forever at prefixLen 1
    // (same divergence cell, same drawn-branch); partitioning by next
    // cell guarantees each bundle's own prefix is >= 2, so every level
    // makes progress. A sibling that ENDS at this already-resolved cell
    // has nothing left to draw at all.
    const byNext = new Map(); // next-cell key -> [suffix paths from divergeCell]
    for (const p of paths) {
      if (p.length === prefixLen) continue;
      const key = cellKey(p[prefixLen]);
      if (!byNext.has(key)) byNext.set(key, []);
      byNext.get(key).push(p.slice(prefixLen - 1));
    }
    for (const bundle of byNext.values()) drawFanoutGroup(bundle, grid, drawn, ctx);
    return;
  }

  // Partition the continuing paths by which direction they leave the
  // divergence cell in.
  const bySide = new Map(); // side -> [remaining suffix paths, each starting at divergeCell]
  for (const p of paths) {
    const next = p[prefixLen];
    if (!next) {
      throw new Error(`Fan-out divergence at [${divergeCell[0]},${divergeCell[1]}]: a sibling path ends exactly at the divergence cell -- this shape isn't supported yet.`);
    }
    const side = sideBetween(divergeCell, next);
    if (!bySide.has(side)) bySide.set(side, []);
    bySide.get(side).push(p.slice(prefixLen - 1));
  }
  const entrySide = prefixLen > 1 ? sideBetween(divergeCell, paths[0][prefixLen - 2]) : 'top';
  const sides = [...bySide.keys()];
  // Whichever side represents "the chain continues to more rows" rides
  // "for free" via the split's own `bottom` output and is processed last;
  // every other side gets its own split peeling it off. When entry is
  // 'top', that's always 'bottom' (OPPOSITE[entrySide] already gives this).
  // When entry is LATERAL, it's 'bottom' too whenever 'bottom' is actually
  // one of the needed exits -- NOT the opposite lateral side, which is
  // only the right answer for a genuine straight-through horizontal pass
  // with nothing continuing further down. Confirmed directly this
  // distinction matters: `right_to_left_and_bottom`/`left_to_right_and_
  // bottom` already exist as real split-block port combinations (see
  // blockCatalog.js's own SPLIT_PORTS) -- entry=lateral, one lateral
  // peel-off, one 'bottom' continuation, drawn as a single split exactly
  // like entry=top's own peel-and-continue shape -- this file's own
  // "unsupported shape" throw for a lateral-entry 'bottom' branch was
  // purely because `straightSide` never considered 'bottom' a candidate
  // here, not because the drawing vocabulary was missing it.
  const straightSide = sides.includes('bottom') ? 'bottom' : OPPOSITE[entrySide];
  sides.sort((a, b) => (a === straightSide ? 1 : b === straightSide ? -1 : 0));

  let row = divergeCell[0];
  const col = divergeCell[1];
  drawn.add(cellKey(divergeCell));

  // A top-entry divergence into exactly two lateral branches (left AND
  // right, no bottom continuation) is a plain T-junction -- the catalog
  // already has a dedicated block for exactly this
  // (`top_to_left_and_right`, blockCatalog.js's SPLIT_PORTS) that peels
  // off BOTH branches in one placement, no "continue to the next row"
  // chaining needed at all. The general loop below assumes whichever
  // side isn't picked as `straightSide` needs its own row further down
  // (correct for a genuine 3+-way chain, or a 2-way split where one
  // branch really does continue straight through) -- but here neither
  // branch continues past this cell, so forcing that model draws a
  // synthetic "split now, wire one row down" pair whose second block
  // doesn't correspond to where either sibling's own path actually goes
  // next (confirmed directly: this is exactly the shape a same-rank
  // fan-out conflict resolved by attemptFanoutRelayer above can produce --
  // a source that used to feed one vertical + one lateral consumer now
  // feeds two purely lateral ones once they're split across different
  // rows).
  if (entrySide === 'top' && sides.length === 2 && sides.includes('left') && sides.includes('right')) {
    grid.placeBlock(row, col, 'split', { borders: 'invisible', label: 'round', direction: 'top_to_left_and_right' });
    if (ctx?.owners && !ctx.owners.has(`${row},${col}`)) ctx.owners.set(`${row},${col}`, ctx.groupRef);
    drawFanoutGroup(bySide.get('left'), grid, drawn, ctx);
    drawFanoutGroup(bySide.get('right'), grid, drawn, ctx);
    return;
  }

  // Same reasoning one step further: a top-entry divergence into BOTH
  // lateral sides AND a bottom continuation, all at one cell, is the
  // catalog's own 3-way split (`top_to_left_and_right_and_bottom`,
  // SPLIT_PORTS) -- one placement, every branch peeled at once. The
  // general chain loop below can't draw this shape at all: it would place
  // the second lateral peel one row down while that sibling's own routed
  // cells still leave from THIS row, producing a disconnected diagram.
  if (entrySide === 'top' && sides.length === 3 && sides.includes('left') && sides.includes('right') && sides.includes('bottom')) {
    grid.placeBlock(row, col, 'split', { borders: 'invisible', label: 'round', direction: 'top_to_left_and_right_and_bottom' });
    if (ctx?.owners && !ctx.owners.has(`${row},${col}`)) ctx.owners.set(`${row},${col}`, ctx.groupRef);
    drawFanoutGroup(bySide.get('left'), grid, drawn, ctx);
    drawFanoutGroup(bySide.get('right'), grid, drawn, ctx);
    drawFanoutGroup(bySide.get('bottom'), grid, drawn, ctx);
    return;
  }

  for (let i = 0; i < sides.length; i++) {
    const side = sides[i];
    const isLast = i === sides.length - 1;
    if (side === straightSide && isLast) {
      // Rides straight through -- no split block needed at all here, the
      // chain simply continues into the next row down. The whole bundle
      // is recursed as ONE call, not one call per sibling: several
      // siblings can still share a FURTHER, deeper divergence past this
      // cell, and only recursing on the bundle together lets the next
      // commonPrefixLen/partition pass see that -- recursing per sibling
      // (each wrapped alone) silently throws that shared structure away,
      // and each one then computes its own entry/exit at that later
      // shared cell independently, colliding (confirmed directly: this
      // is exactly what broke gimli_bitsliced_sbox/ascon_linear_layer).
      drawFanoutGroup(bySide.get(side), grid, drawn, ctx);
      continue;
    }
    if (side !== 'left' && side !== 'right') {
      throw new Error(`Fan-out divergence at [${row},${col}] needs a non-lateral (${side}) branch mid-chain -- unsupported shape.`);
    }
    const continuesDown = !isLast;
    if (continuesDown) {
      // entrySide/side name the split directly, same vocabulary as `wire`'s
      // own direction (every (entrySide, side) pair reaching here is one of
      // SPLIT_PORTS's 2-output combinations: 'top' pairs with either
      // lateral side, 'left'/'right' can only pair with the other one).
      grid.placeBlock(row, col, 'split', { borders: 'invisible', label: 'round', direction: `${entrySide}_to_${side}_and_bottom` });
    if (ctx?.owners && !ctx.owners.has(`${row},${col}`)) ctx.owners.set(`${row},${col}`, ctx.groupRef);
    } else {
      // No duplication happening here at all (this is the last remaining
      // path and it doesn't continue straight down) -- a single-in,
      // single-out turn is just a `wire`, not a `split` (there's no
      // SPLIT_PORTS entry for a side-only, no-bottom shape, on purpose --
      // see split's own params comment).
      grid.placeBlock(row, col, 'wire', { borders: 'invisible', label: 'round', direction: `${entrySide}_to_${side}` });
    if (ctx?.owners && !ctx.owners.has(`${row},${col}`)) ctx.owners.set(`${row},${col}`, ctx.groupRef);
    }
    // Same bundle-not-per-sibling recursion as the straight-through case
    // above, for the identical reason.
    drawFanoutGroup(bySide.get(side), grid, drawn, ctx);
    if (!continuesDown) break;
    row += 1;
  }
}

// Runs ELK layout on `graph` (from buildElkGraph) and draws the result
// into a fresh Grid, using `meta` to know which real block type/params
// belong at each ELK node id.
// A port name is either the plain 'in'/'out' (a 1-word node) or 'in<N>'/
// 'out<N>' (word N of a multi-word node, see buildElkGraph) -- resolves an
// "id.port" endpoint reference to the actual grid cell it lands on,
// offsetting into the node's own already-placed column by word index.
function endpointCell(ref, nodeCell) {
  const dot = ref.lastIndexOf('.');
  const nodeId = ref.slice(0, dot);
  const port = ref.slice(dot + 1);
  const [row, col] = nodeCell.get(nodeId);
  const m = /^(?:in|out)(\d+)$/.exec(port);
  return m ? [row, col + Number(m[1])] : [row, col];
}

// Computes every node's placed cell and every edge-group's routed cell
// path, given a specific `rowIndex` function -- pulled out of
// layoutToGrid so it can be re-run against a *patched* rowIndex (see
// planPlacement below) without redoing the ELK layout itself.
// `columnOverride` (optional, elk node id -> column) forces specific
// nodes to a column other than what `colIndex(n.x)` would naturally give
// them -- see straightenTrunk below, which is the only caller that passes
// this. Since every edge's own cells are derived from `nodeCell` *after*
// it's built (via endpointCell), overriding a node's column here
// automatically and correctly re-routes every edge touching it too, with
// no separate per-edge patching needed.
function computeCellsWith(result, meta, rowIndex, colIndex, columnOverride) {
  const nodeCell = new Map(); // elk node id -> [row, col] (its own top-left cell)
  for (const n of result.children) {
    const col = columnOverride?.has(n.id) ? columnOverride.get(n.id) : colIndex(n.x);
    nodeCell.set(n.id, [rowIndex(n.y), col]);
  }
  const occupied = new Set();
  for (const cell of nodeCell.values()) occupied.add(cellKey(cell));

  // Every port's declared side, straight from the graph buildElkGraph
  // produced (elk.layout mutates that same object, so the input
  // layoutOptions survive): explicit 'elk.port.side' for FIXED_SIDE
  // ports, and by-name for FIXED_POS multi-word ports (in<k> rows sit at
  // y=0/NORTH, out<k> at y=1/SOUTH by construction -- see makeFixedPosPort).
  const portSide = new Map(); // "nodeId.port" -> 'NORTH'|'SOUTH'|'WEST'|'EAST'
  for (const n of result.children) {
    for (const p of n.ports || []) {
      const name = p.id.slice(p.id.lastIndexOf('.') + 1);
      const side = p.layoutOptions?.['elk.port.side'] || (name.startsWith('in') ? 'NORTH' : 'SOUTH');
      portSide.set(p.id, side);
    }
  }

  // Group edges by (source node id, source port name) to detect fan-out.
  const groups = new Map(); // "nodeId.port" -> [cell-path, ...]
  for (const e of result.edges) {
    const sourceRef = e.sources[0];
    const targetRef = e.targets[0];
    const sourceCell = endpointCell(sourceRef, nodeCell);
    const targetCell = endpointCell(targetRef, nodeCell);
    const middle = pointsOf(e)
      .slice(1, -1)
      .map((p) => [rowIndex(p.y), colIndex(p.x)]);
    // Almost every source port in this graph faces SOUTH (a plain node's
    // own 'out', or a multi-word node's per-word 'out<N>') -- so the cell
    // directly below the source is a geometric guarantee, regardless of
    // what a classified middle point says. Forcing it explicitly matters
    // for fan-out: two sibling edges leaving the same port must share
    // this cell exactly, or divergence-detection (drawFanoutGroup) can
    // end up computing the split point as the source's own already-
    // occupied cell instead of one row below it. The one exception is a
    // 'compact'-strategy node laid sideways (see buildElkGraph's
    // `sideOutput`) -- its real out port faces WEST/EAST instead, so its
    // forced first step must follow suit, or the very first cell of its
    // own route would claim a column its neighbor doesn't actually reach.
    const sourceNodeId = sourceRef.slice(0, sourceRef.lastIndexOf('.'));
    const sourceParams = meta.get(sourceNodeId)?.params;
    const forcedFirstStep =
      sourceParams?.portLeft === 'out'
        ? [sourceCell[0], sourceCell[1] - 1]
        : sourceParams?.portRight === 'out'
          ? [sourceCell[0], sourceCell[1] + 1]
          : [sourceCell[0] + 1, sourceCell[1]];
    // Symmetric to forcedFirstStep: the cell the route must occupy
    // immediately before entering the target is fully determined by the
    // TARGET PORT's own side -- information endpointCell otherwise
    // discards when it collapses the port reference to the node's cell.
    // Without this, quantization is free to end a route on whichever side
    // its last bend happens to land, and two edges targeting DIFFERENT
    // ports of one node can flatten into the same approach corridor --
    // confirmed directly on norx_quarterround ([19,4]: one group's
    // east-side approach corridor reused by another group's edge that
    // actually targets a different port) and ascon[rounds=1] ([3,14],
    // same shape). For a route already approaching from the correct side
    // the forced waypoint is already on the path, so this is a strict
    // no-op for every previously-drawable edge (a wrong-side approach
    // could never pass checkConnectivity anyway).
    const tSide = portSide.get(targetRef);
    const forcedLastStep =
      tSide === 'WEST'
        ? [targetCell[0], targetCell[1] - 1]
        : tSide === 'EAST'
          ? [targetCell[0], targetCell[1] + 1]
          : [targetCell[0] - 1, targetCell[1]]; // NORTH (the default for every in-port; bottom is never an in-port)
    const rawPoints = [sourceCell, forcedFirstStep, ...middle, forcedLastStep, targetCell];
    let cells = straightenAscents(cellsAlong(rawPoints));
    // Wrong-side/wrong-row flattened approach: the walk above can only
    // honor forcedLastStep if the route's own quantized bend points already
    // arrive via the correct row/side -- when they instead flatten the
    // around-the-node loop onto the TARGET's own row (rather than the row
    // forcedLastStep expects to approach from), the walk crosses the target
    // cell to reach the waypoint and collapseBacktracks silently truncates
    // the detour away, leaving an approach into the wrong port side (both a
    // connectivity error and a corridor conflict with whatever edge
    // genuinely owns that side/row). Originally written for WEST/EAST
    // target ports only (confirmed on norx_quarterround's WEST-port edge
    // flattened into the EAST corridor) -- the identical flattening shape
    // also hits NORTH ports (confirmed on aes_round_without_roundkey: a
    // multi-word call's 4th argument, needing to jog one column left into
    // its own consecutive word-slot, quantizes its horizontal jog onto the
    // target's own row instead of the row directly above it, producing a
    // lateral 'exit=left' approach into a port that only ever accepts
    // 'exit=bottom' -- the exact same shape, just a different tSide), so
    // this no longer excludes NORTH. The geometry itself was always
    // side-agnostic (it operates purely on targetRow/forcedLastStep, never
    // branching on tSide internally) -- only the guard was too narrow.
    // Downward-only wires can never recover from the wrong side/row AT the
    // target's own row (that would need an upward move), so lift the
    // trailing target-row corridor one row up, run it across to the correct
    // approach column there, and descend into the port. A no-op for every
    // edge whose quantized path already arrives correctly (the overwhelming
    // common case, for every tSide): `penult` already equals `forcedLastStep`
    // there, so the inner `if` never fires.
    if (cells.length >= 2) {
      const penult = cells[cells.length - 2];
      if (penult[0] !== forcedLastStep[0] || penult[1] !== forcedLastStep[1]) {
        const targetRow = targetCell[0];
        let j = cells.length - 2;
        while (j >= 0 && cells[j][0] === targetRow) j--;
        if (j >= 0 && j < cells.length - 2) {
          const rebuilt = cells.slice(0, j + 1);
          for (let k = j + 1; k <= cells.length - 2; k++) rebuilt.push([targetRow - 1, cells[k][1]]);
          let c = rebuilt[rebuilt.length - 1][1];
          while (c !== forcedLastStep[1]) {
            c += Math.sign(forcedLastStep[1] - c);
            rebuilt.push([targetRow - 1, c]);
          }
          rebuilt.push(forcedLastStep, [targetCell[0], targetCell[1]]);
          cells = collapseBacktracks(rebuilt);
        }
      }
    }
    avoidNodeObstacles(cells, occupied);
    if (!groups.has(sourceRef)) groups.set(sourceRef, []);
    groups.get(sourceRef).push(cells);
  }
  return { nodeCell, groups };
}

// ELK's own column/row banding (see buildAxisIndex) glues a transiting
// bend point onto whichever real node's band it happens to fall near --
// harmless when that's a different row/column, but when the node also
// sits at this edge's own row/column, the wire's INTERIOR cell (never a
// real port -- only cells[0]/cells[last] are) lands squarely on that
// node's own cell. Confirmed directly on ascon_nonlinear_layer and
// type3_feistel[rounds=1]. Only the ordinary case an orthogonal path
// actually produces -- a straight-through obstacle, with the cells on
// either side sharing one axis with it -- is corrected here, by bumping
// that one cell out to an adjacent unoccupied row/column and back (a
// "notch" detour that changes only how the path gets there, never what
// it connects). A corner landing exactly on an obstacle has never been
// observed, so it's left to drawRouteCell's pre-existing collision error
// rather than guessed at.
function avoidNodeObstacles(cells, occupied) {
  let i = 1;
  while (i < cells.length - 1) {
    if (occupied.has(cellKey(cells[i]))) detourAroundObstacle(cells, i, (row, col) => row >= 0 && col >= 0 && !occupied.has(cellKey([row, col])));
    i++;
  }
}

// `free(row, col)` abstracts what "empty" means to each caller: a static
// occupied-cells set here (avoidNodeObstacles, checked before any drawing
// happens) versus the live grid (drawInterior's own dynamic obstacle case
// below, checked incrementally as drawing proceeds) -- same geometry
// either way, just a different notion of "nothing is there yet".
//
// A candidate notch is only accepted once every cell it introduces draws
// as a valid turn (present in REWIRE_DIRECTION) against its now-fixed
// neighbors -- not just once it's geometrically unoccupied. This matters
// asymmetrically: every wire in this drawing model flows strictly
// top-to-bottom (REWIRE_DIRECTION has no entry for exit='top' or
// entry='bottom' -- see its own comment), so a COLUMN notch around a
// vertical (top/bottom) obstacle always stays valid (the detour only ever
// adds left/right turns), but a ROW notch around a HORIZONTAL
// (left/right) obstacle provably can't: reconnecting to the same row
// after bumping up or down always needs one leg to travel back the
// "wrong" way (confirmed by direct construction, both directions, on
// xoodoo_theta_transformation -- accepting it unchecked drew a wire this
// project's own vocabulary can't render, surfacing later as a confusing
// "Unroutable turn" instead of this function correctly reporting no
// notch exists). Checked generically, not hardcoded per axis, so this
// stays correct if the vocabulary's directionality assumption ever
// changes.
function detourAroundObstacle(cells, index, free) {
  const [r, c] = cells[index];
  const [pr, pc] = cells[index - 1];
  const [nr, nc] = cells[index + 1];
  const tryNotch = (a, b, cc) => {
    if (!free(...a) || !free(...b) || !free(...cc)) return false;
    const seq = [[pr, pc], a, b, cc, [nr, nc]];
    for (let k = 1; k < seq.length - 1; k++) {
      const entry = sideBetween(seq[k], seq[k - 1]);
      const exit = sideBetween(seq[k], seq[k + 1]);
      if (!REWIRE_DIRECTION[`${entry},${exit}`]) return false;
    }
    cells.splice(index, 1, a, b, cc);
    return true;
  };
  if (pr === r && nr === r) {
    for (const d of [-1, 1]) {
      const dr = r + d;
      if (tryNotch([dr, pc], [dr, c], [dr, nc])) return true;
    }
  } else if (pc === c && nc === c) {
    for (const d of [-1, 1]) {
      const dc = c + d;
      if (tryNotch([pr, dc], [r, dc], [nr, dc])) return true;
    }
  }
  return false;
}

// A fan-out group is unroutable exactly when one sibling's own path ends
// *at* the group's shared-prefix cell while another sibling needs to
// keep going past it: that cell is that sibling's own destination node
// (a real, already-placed block -- `forcedFirstStep` above is what makes
// a short, directly-adjacent sibling's destination coincide with the
// group's divergence point in the first place), and a `split` marker
// can no more share a cell with a real node than any other two blocks
// can. Confirmed by direct construction, not guessed: this is the exact
// shape `xor(F(input), input)` produces once `F(input)` is the vertical
// argument (`input` immediately adjacent below itself, then also
// needing to reach `xor` laterally) -- there is no way to draw a split
// where a real block already sits, no matter how the drawing code is
// written. Returns the [row, col] cell that needs a fresh, empty buffer
// row inserted directly above it (see planPlacement) to make room, or
// null if every group in `groups` is drawable as-is.
// A group's FIRST divergence isn't the only place a short sibling can sit:
// drawFanoutGroup partitions the continuing suffixes by exit side and
// recurses, and a sub-bundle can have its own, deeper divergence with the
// identical short+longer shape (confirmed directly on ascon[rounds=1]: a
// 3-path bottom-side bundle whose nested divergence at [8,8] is one
// sibling's own destination while two more continue laterally -- the
// top-level check never saw it, so the buffer-row/relayer machinery never
// got the chance to fix it and drawing hit the raw "sibling path ends
// exactly at the divergence cell" throw instead). Mirrors drawFanoutGroup's
// own partition-and-recurse walk, just detecting instead of drawing.
// Termination: every sub-bundle shares its divergence cell AND the same
// next cell, so its own prefix is >= 2 -- each level strips >= 1 cell.
function findConflictInBundle(paths) {
  if (paths.length < 2) return null;
  const prefixLen = commonPrefixLen(paths);
  const hasShortSibling = paths.some((p) => p.length === prefixLen);
  const hasLongerSibling = paths.some((p) => p.length > prefixLen);
  if (hasShortSibling && hasLongerSibling) return paths[0][prefixLen - 1];
  if (!hasLongerSibling) return null; // every sibling ends together -- no divergence left
  const byNext = new Map(); // next-cell key -> [suffix paths from the divergence cell]
  for (const p of paths) {
    const key = cellKey(p[prefixLen]);
    if (!byNext.has(key)) byNext.set(key, []);
    byNext.get(key).push(p.slice(prefixLen - 1));
  }
  for (const bundle of byNext.values()) {
    const found = findConflictInBundle(bundle);
    if (found) return found;
  }
  return null;
}

function findAdjacentFanoutConflict(groups) {
  for (const paths of groups.values()) {
    const found = findConflictInBundle(paths);
    if (found) return found;
  }
  return null;
}

// A same-rank fan-out conflict (see findAdjacentFanoutConflict above) is
// NOT always fixable by shifting rows: when the conflicting divergence
// cell is a real node (`n5` below) sitting on the exact same ELK layer as
// the short sibling's own destination (`n2`) -- both direct 1-hop
// consumers of the same shared leaves -- planPlacement's uniform
// "shift every row at/after the conflict down by one" moves the two
// together every time (they started on the same rank), so the conflict
// just reproduces one row lower, forever (confirmed directly: minimal
// repro `output = xor(xor(input1, input2), and(input1, input2))` cycles
// through all 20 buffer-row attempts with the same two nodes landing on
// the same row every time).
//
// The fix needs *real* per-node scheduling -- moving the short sibling's
// destination (and everything downstream of it, so it doesn't end up
// causally *before* something it depends on) onto a genuinely later ELK
// layer, without dragging its unrelated same-rank sibling along -- which
// is exactly what ELK's own `elk.layered.layering.strategy: 'INTERACTIVE'`
// mode does when combined with seeded per-node `y` positions (confirmed
// directly by experiment against real elkjs before integrating here, the
// same discipline as every other ELK lever in this file): re-running
// layout with only the offending node's own subtree nudged onto a later
// y-band re-derives layering (not just a mechanical row insertion) *and*
// redoes crossing-minimization/coordinate-assignment for the whole graph,
// so the rest of the diagram settles wherever ELK naturally wants it
// rather than inheriting stale columns from the first pass.
//
// `elk.layout()` mutates its input graph object in place (confirmed
// directly: `elk.layout(graph) === graph`) and returns that same
// reference -- so `result`/`graph` here are one and the same object, and
// this function's own re-layout call further mutates it. Snapshots the
// pre-relayer state first (structuredClone, since children/edges are
// plain JSON-shaped data) so a relayer attempt that doesn't actually
// clear the conflict can be cleanly undone, leaving the existing
// buffer-row loop to run against byte-identical state to before this
// function was ever called.
//
// Returns a fresh, conflict-free ELK result on success, or null (with
// `graph` restored to its pre-attempt state) if this specific lever
// doesn't resolve it -- callers fall back to the pre-existing behavior
// unchanged in that case, so this is a strict addition, never a
// regression risk for a shape it can't help.
async function attemptFanoutRelayer(graph, meta) {
  const { nodeCell, groups } = computeCellsWith(graph, meta, buildBaseRowIndex(graph), buildBaseColIndex(graph));
  const conflictCell = findAdjacentFanoutConflict(groups);
  if (!conflictCell) return null;

  const offendingId = [...nodeCell.entries()].find(([, cell]) => cell[0] === conflictCell[0] && cell[1] === conflictCell[1])?.[0];
  if (!offendingId) return null; // defensive -- every conflict cell is, by construction, a real node's own cell

  // Transitive successors of the offending node (itself included): every
  // node causally downstream of it must move down with it, or the graph
  // would show a value used before it's computed.
  const forward = new Map(); // id -> [target id, ...]
  for (const e of graph.edges) {
    const from = e.sources[0].slice(0, e.sources[0].lastIndexOf('.'));
    const to = e.targets[0].slice(0, e.targets[0].lastIndexOf('.'));
    if (!forward.has(from)) forward.set(from, []);
    forward.get(from).push(to);
  }
  const toBump = new Set([offendingId]);
  const queue = [offendingId];
  while (queue.length) {
    for (const next of forward.get(queue.pop()) || []) {
      if (!toBump.has(next)) { toBump.add(next); queue.push(next); }
    }
  }

  // "One layer's worth" of y, derived from the actual layout rather than
  // assumed: the smallest positive gap between two distinct y values
  // already present. Comfortably separates the offending node from its
  // former same-rank sibling without needing to know ELK's own internal
  // spacing constant.
  const ys = [...new Set(graph.children.map((n) => n.y))].sort((a, b) => a - b);
  let bandSpacing = null;
  for (let i = 1; i < ys.length; i++) {
    const gap = ys[i] - ys[i - 1];
    if (bandSpacing === null || gap < bandSpacing) bandSpacing = gap;
  }
  if (!bandSpacing) return null; // defensive -- every real corpus graph has 2+ distinct y bands once a conflict exists

  const snapshot = structuredClone({ children: graph.children, edges: graph.edges, layoutOptions: graph.layoutOptions });

  // A single band is enough to clear the offending node's own former
  // rank in the simple case (confirmed on the minimal repro), but a
  // densely co-ranked real diagram (e.g. an S-box with several and/xor
  // siblings sharing a rank) can still have something else already
  // occupying the very next rank the bumped node lands on -- tried again
  // with progressively more bands, up to the number of distinct ranks
  // already in the graph (a real, if loose, upper bound: the offending
  // node can never need to move past every existing rank), reverting
  // `graph` to the pre-attempt snapshot between tries so each attempt
  // starts clean rather than compounding on the previous one's failed
  // mutation.
  for (let multiplier = 1; multiplier <= ys.length; multiplier++) {
    for (const n of graph.children) {
      if (toBump.has(n.id)) n.y = snapshot.children.find((c) => c.id === n.id).y + bandSpacing * multiplier;
    }
    graph.layoutOptions = { ...snapshot.layoutOptions, 'elk.layered.layering.strategy': 'INTERACTIVE' };

    const relaid = await new ELK().layout(graph);
    const freshRowIndex = buildBaseRowIndex(relaid);
    const freshColIndex = buildBaseColIndex(relaid);
    const { groups: newGroups } = computeCellsWith(relaid, meta, freshRowIndex, freshColIndex);
    if (!findAdjacentFanoutConflict(newGroups)) return relaid;
    Object.assign(graph, structuredClone(snapshot));
  }
  return null;
}

// A DIFFERENT drawability gap than findAdjacentFanoutConflict's own
// same-rank fan-out shape: a routed path that needs to pass STRAIGHT
// HORIZONTALLY (entry=left,exit=right or entry=right,exit=left) through a
// cell some OTHER, unrelated real node already occupies. Confirmed root
// cause of gimli_bitsliced_sbox (and the sibling gimli/norx/ascon/xoodoo/
// chacha files sharing the same shape): a widely fanning-out value (e.g.
// gimli_bitsliced_sbox's `temp[1]`) has 4+ direct consumers ELK lands on
// the SAME rank, spread across many columns -- reaching the *far* one
// means a lateral wire has to cross straight through a *closer* sibling
// consumer's own cell, which sits on that exact row precisely because it
// is a same-rank co-consumer. This is provably NOT locally fixable by
// detourAroundObstacle's own notch (see its own comment: a ROW notch
// around a HORIZONTAL obstacle always needs one leg to travel back the
// "wrong" way, impossible under this file's strictly downward-only wire
// vocabulary) -- unlike a VERTICAL straight pass through an obstacle,
// which a column notch handles today. Nor is it the same shape
// findAdjacentFanoutConflict detects (no sibling path ends exactly at the
// divergence cell here -- every sibling's path is already a full,
// otherwise-valid route, it just happens to transit a cell a real node
// owns). Checked against every path in every group (not just divergence
// points), since the obstruction can sit anywhere along an already-
// diverged single-sibling path, not only at a fan-out's own branch cell.
//
// The obstacle isn't always a real ELK *node* -- a fan-out divergence
// cell (where a `split` block will need to be placed, see
// commonPrefixLen/drawFanoutGroup) is just as immovable: a split can no
// more merge with a crossing wire than any other real block can.
// Confirmed directly as the next conflicts gimli_bitsliced_sbox's own
// `temp[1]`/`temp[2]` hit once every real-node obstruction is resolved --
// a wide fan-out's own lateral reach runs straight through a cell some
// OTHER already-diverged branch's own divergence point occupies. This
// isn't only a DIFFERENT group's divergence: two branches of the very
// SAME group's own fan-out tree can also cross this way (confirmed
// directly: temp[2]'s own 4-way split has one branch's fully-resolved
// route pass back through a *different* branch's own divergence cell,
// an ELK bend-point-quantization artifact, not a legitimate shared
// prefix) -- so ownership is tracked per PATH (via divergenceOwnership,
// which specific paths legitimately pass through a given divergence cell
// as part of ITS OWN subtree), not per group; a path outside a
// divergence's own owning set is a conflict regardless of which group it
// belongs to.
//
// Returns `{ cell, offendingId }` -- `offendingId` is always the
// CROSSING path's own target node (this path's last cell, always a real
// node's cell by construction): bumping the divergence's own source
// instead (its whole, often near-whole-graph downstream) measured
// unstable in practice (confirmed directly: re-layout under INTERACTIVE
// strategy reshuffled unrelated crossing-minimization choices enough to
// keep manifesting fresh conflicts elsewhere rather than converging) --
// bumping the crossing path's own target is the much narrower, more local
// change that actually lets ELK re-derive a different bend row for just
// this one edge, and works identically whether the obstacle is a real
// node or a divergence cell. Returns null if nothing conflicts.
function findLateralObstacleConflict(nodeCell, groups) {
  const nodeAt = new Map(); // cellKey -> nodeId, for every real placed node's own cell
  for (const [id, cell] of nodeCell) nodeAt.set(cellKey(cell), id);
  const owners = divergenceOwnership(groups); // cellKey -> Set(path) of paths that legitimately pass through it
  for (const paths of groups.values()) {
    for (const path of paths) {
      for (let i = 1; i < path.length - 1; i++) {
        const key = cellKey(path[i]);
        const nodeId = nodeAt.get(key);
        const ownerSet = owners.get(key);
        const isForeignDivergence = ownerSet !== undefined && !ownerSet.has(path);
        if (!nodeId && !isForeignDivergence) continue;
        const entry = sideBetween(path[i], path[i - 1]);
        const exit = sideBetween(path[i], path[i + 1]);
        if ((entry === 'left' && exit === 'right') || (entry === 'right' && exit === 'left')) {
          const offendingId = nodeAt.get(cellKey(path[path.length - 1])) || nodeId;
          if (!offendingId) continue; // defensive -- should be unreachable
          return { cell: path[i], offendingId };
        }
      }
    }
  }
  return null;
}

// For every fan-out group, walks the identical recursive
// partition-by-next-cell tree commonPrefixLen/drawFanoutGroup use, but
// (unlike collectDivergenceCells, which is keyed one-entry-per-cell and
// so can't represent two different divergences landing on the same cell
// at all) records, per divergence cell, the exact SET of original path
// arrays (by reference -- never copied/sliced, so `===` identity survives
// the recursion) that legitimately pass through it as part of that
// divergence's own subtree. Walking with an {orig, offset} pair instead
// of drawFanoutGroup's own `p.slice(prefixLen - 1)` avoids copying paths
// just to track this -- `commonPrefixLen`-equivalent length is
// recomputed the same way, just indexed through each entry's own offset.
function divergenceOwnership(groups) {
  const owners = new Map(); // cellKey -> Set(original path array reference)
  function walk(entries) {
    if (entries.length < 2) return;
    let prefixLen = 1;
    outer: for (; ; prefixLen++) {
      const candidate = entries[0].orig[entries[0].off + prefixLen];
      if (!candidate) break;
      for (const e of entries) {
        const c = e.orig[e.off + prefixLen];
        if (!c || c[0] !== candidate[0] || c[1] !== candidate[1]) break outer;
      }
    }
    const key = cellKey(entries[0].orig[entries[0].off + prefixLen - 1]);
    if (!owners.has(key)) owners.set(key, new Set());
    for (const e of entries) owners.get(key).add(e.orig);
    const byNext = new Map();
    for (const e of entries) {
      const nextIdx = e.off + prefixLen;
      if (nextIdx >= e.orig.length) continue;
      const k = cellKey(e.orig[nextIdx]);
      if (!byNext.has(k)) byNext.set(k, []);
      byNext.get(k).push({ orig: e.orig, off: e.off + prefixLen - 1 });
    }
    for (const bundle of byNext.values()) walk(bundle);
  }
  for (const paths of groups.values()) walk(paths.map((p) => ({ orig: p, off: 0 })));
  return owners;
}

// Cumulative-rounds cap for attemptLateralObstacleRelayer below -- a
// widely fanning-out value's own conflicts can compound (gimli_bitsliced_
// sbox's `temp[1]` and `temp[2]` each need their own, separate bump before
// the whole diagram clears), so a single-shot "bump one node, try a few
// multipliers" attempt (as attemptFanoutRelayer's own simpler shape needs)
// isn't always enough -- this allows the bump SET to grow across rounds
// (see the function's own comment). Bounded, matching this file's other
// small round caps (RIPUP_MAX_ROUNDS, DRAW_BUFFER_MAX) -- not expected to
// ever actually need many rounds for a real corpus file.
const LATERAL_RELAYER_MAX_ROUNDS = 12;

// Same "nudge the offending node (and everything transitively downstream
// of it) onto a later ELK layer, re-run layout with
// `layering.strategy: INTERACTIVE`, keep only if the conflict is actually
// gone, else restore the pre-attempt snapshot" mechanism as
// attemptFanoutRelayer above -- confirmed-safe pattern, re-triggered here
// by findLateralObstacleConflict's own, different predicate instead of
// findAdjacentFanoutConflict's. Deliberately NOT refactored into one
// shared helper with attemptFanoutRelayer: keeping them fully separate
// means this new lever can never perturb the existing, already-battle-
// tested fan-out relayer's own behavior, at the cost of some duplication.
//
// Unlike attemptFanoutRelayer's single offending node, this accumulates
// bumps across ROUNDS rather than just retrying bigger multipliers for one
// fixed node: confirmed necessary on gimli_bitsliced_sbox itself -- fixing
// `temp[1]`'s own conflict (a small, local downstream) reveals a SEPARATE,
// independent conflict from `temp[2]`'s own wide fan-out crossing the same
// crowded rank, which needs its OWN, different node bumped; retrying only
// ever-bigger multipliers for the FIRST offender alone (tried first, see
// project history for this session) either cycled without converging or
// gave up outright. Each round finds whatever conflict currently exists
// (possibly a fresh one the previous round's bump didn't touch, possibly
// the SAME one needing a bigger gap than last time), adds -- or escalates
// -- that specific node's own transitive downstream closure in a
// monotonically growing `bumpLevel` map, then reapplies EVERY accumulated
// bump from the pristine snapshot (never compounding on a previous
// relayout's own already-perturbed y, which drifted uncontrollably when
// tried -- always re-deriving from the same fixed baseline keeps each
// round's result reproducible and easy to reason about). Gives up (restores
// the snapshot, returns null) if no round within the cap achieves a fully
// conflict-free layout -- callers fall back to pre-existing behavior
// unchanged in that case, so this is a strict addition, never a regression
// risk for a shape it can't help.
async function attemptLateralObstacleRelayer(graph, meta) {
  const { nodeCell, groups } = computeCellsWith(graph, meta, buildBaseRowIndex(graph), buildBaseColIndex(graph));
  let conflict = findLateralObstacleConflict(nodeCell, groups);
  if (!conflict) return null;

  // findLateralObstacleConflict is a conservative OVER-approximation, not a
  // guarantee of an actual draw failure -- confirmed directly (full corpus
  // regeneration, unbalanced_feistel_explicit_f_function[rounds=1,
  // aligned=true]'s own 'compact'-strategy layout): it can flag a cell this
  // predicate calls "unconditionally unfixable" that the REAL drawing
  // pipeline (drawFanoutGroup's own bundling/collapseBacktracks/reroute
  // machinery, none of which this predicate re-derives) still draws just
  // fine as-is. Left unguarded, the relayer would "fix" a file that was
  // never actually broken, silently perturbing its geometry for no reason
  // (still equivalent, but a real, unintended behavior change this file's
  // own "strict addition, never a regression risk" contract promises
  // against). tryDraw on the UNMODIFIED, pre-bump geometry is the same
  // authoritative, real-pipeline bar this function already holds its own
  // relayout candidates to (see below) -- checked first, before spending
  // any relayout effort, so a false positive here costs one extra tryDraw
  // call and nothing else.
  const childIds = graph.children.map((n) => n.id);
  try {
    tryDraw(childIds, nodeCell, groups, meta);
    return null; // draws fine already -- nothing to fix, leave it untouched
  } catch {
    // confirmed a genuine failure -- proceed to relayer below
  }

  const forward = new Map(); // id -> [target id, ...]
  for (const e of graph.edges) {
    const from = e.sources[0].slice(0, e.sources[0].lastIndexOf('.'));
    const to = e.targets[0].slice(0, e.targets[0].lastIndexOf('.'));
    if (!forward.has(from)) forward.set(from, []);
    forward.get(from).push(to);
  }
  function closureOf(seed) {
    const set = new Set([seed]);
    const queue = [seed];
    while (queue.length) {
      for (const next of forward.get(queue.pop()) || []) {
        if (!set.has(next)) { set.add(next); queue.push(next); }
      }
    }
    return set;
  }

  const ys = [...new Set(graph.children.map((n) => n.y))].sort((a, b) => a - b);
  let bandSpacing = null;
  for (let i = 1; i < ys.length; i++) {
    const gap = ys[i] - ys[i - 1];
    if (bandSpacing === null || gap < bandSpacing) bandSpacing = gap;
  }
  if (!bandSpacing) return null;

  const snapshot = structuredClone({ children: graph.children, edges: graph.edges, layoutOptions: graph.layoutOptions });
  const bumpLevel = new Map(); // id -> current multiplier level (monotonically non-decreasing across rounds)
  let targetId = conflict.offendingId; // which node's own closure the NEXT round should escalate

  for (let round = 0; round < LATERAL_RELAYER_MAX_ROUNDS; round++) {
    const closure = closureOf(targetId);
    const nextLevel = (bumpLevel.get(targetId) || 0) + 1;
    for (const id of closure) bumpLevel.set(id, Math.max(bumpLevel.get(id) || 0, nextLevel));

    Object.assign(graph, structuredClone(snapshot));
    for (const n of graph.children) {
      const level = bumpLevel.get(n.id);
      if (level) n.y = snapshot.children.find((c) => c.id === n.id).y + bandSpacing * level;
    }
    graph.layoutOptions = { ...snapshot.layoutOptions, 'elk.layered.layering.strategy': 'INTERACTIVE' };

    const relaid = await new ELK().layout(graph);
    const freshRowIndex = buildBaseRowIndex(relaid);
    const freshColIndex = buildBaseColIndex(relaid);
    const { nodeCell: freshNodeCell, groups: freshGroups } = computeCellsWith(relaid, meta, freshRowIndex, freshColIndex);
    conflict = findLateralObstacleConflict(freshNodeCell, freshGroups);
    if (!conflict) {
      // Absence of THIS specific conflict shape is necessary but not
      // sufficient -- confirmed directly: a relayout can clear it while
      // introducing a DIFFERENT drawing problem this predicate never
      // checks for (observed on gimli_bitsliced_sbox itself, first
      // attempt at this fix: a bumped fan-out's own path came back
      // through its already-visited trunk column from the side, a
      // same-group self-crossing drawFanoutGroup's strict divergence-tree
      // model can't represent -- an ELK-relayout artifact, not the
      // conflict this lever targets). tryDraw reuses the real drawing
      // pipeline end to end (exactly compactColumns/straightenTrunk's own
      // "full redraw, discard on failure" bar) as the actual, authoritative
      // check -- only a layout that genuinely draws is ever accepted.
      try {
        tryDraw(childIds, freshNodeCell, freshGroups, meta);
        return relaid;
      } catch {
        // Drew into some OTHER problem with no lateral-obstacle conflict
        // left to point at a *different* node -- retry the SAME target at
        // an even bigger gap rather than giving up on the very first such
        // case (confirmed to matter directly: a bigger gap can still avoid
        // an ELK-relayout artifact a smaller one didn't).
        conflict = { offendingId: targetId };
      }
    }
    targetId = conflict.offendingId;
  }
  Object.assign(graph, structuredClone(snapshot));
  return null;
}

// Finds a `rowIndex` that leaves every fan-out group drawable, patching
// in one extra buffer row at a time (re-deriving nodeCell/groups fully
// each time, since a single insertion can shift where later conflicts --
// or the *same* conflict, now one row down -- show up) rather than
// trying to patch already-computed cell paths after the fact. Each
// patched `rowIndex` simply adds 1 to every row at/after the conflict
// row it was built to fix; composed across iterations, this is
// equivalent to `Grid.insertRow` at each of those rows in turn, but
// derived from the *raw* ELK coordinates every time -- so a node whose
// own row doesn't move (anything strictly above every insertion so far)
// keeps computing the exact same forced first step it always did,
// while the one node that needs to move (e.g. a fan-out's short sibling,
// directly adjacent to its source) genuinely does, correctly reopening
// the row between them. Bounded at 20 iterations as a backstop against
// a shape this can't resolve -- not expected to ever actually hit it.
async function planPlacement(result, meta, graph) {
  let rowIndex = buildBaseRowIndex(result);
  let colIndex = buildBaseColIndex(result);
  for (let attempt = 0; attempt < 20; attempt++) {
    const { nodeCell, groups } = computeCellsWith(result, meta, rowIndex, colIndex);
    const conflictCell = findAdjacentFanoutConflict(groups);
    // rowIndex/colIndex returned alongside -- straightenTrunk (see below,
    // 'straight-trunk' strategy only) needs the exact same settled base
    // indices to re-run computeCellsWith with its own columnOverride.
    if (conflictCell === null) {
      // A DIFFERENT drawability gap than the fan-out one just ruled out --
      // see findLateralObstacleConflict's own comment. Only checked once
      // the fan-out check is already clear (both are pre-draw checks over
      // the same nodeCell/groups, and the fan-out lever is the more
      // established of the two -- no observed case needs both at once, so
      // there's no ordering dilemma to resolve here). A no-op (null) for
      // the overwhelming common case leaves this branch's own `return`
      // completely unchanged from before this check existed.
      const lateralConflict = findLateralObstacleConflict(nodeCell, groups);
      if (!lateralConflict) return { nodeCell, groups, rowIndex, colIndex };

      const relaidLateral = await attemptLateralObstacleRelayer(graph, meta);
      if (relaidLateral) {
        result = relaidLateral;
        rowIndex = buildBaseRowIndex(result);
        colIndex = buildBaseColIndex(result);
        continue;
      }
      // No safe relayer found for this specific conflict -- return exactly
      // as if this check didn't exist, leaving the rest of the pipeline
      // (drawing/negotiation) to handle it exactly as before.
      return { nodeCell, groups, rowIndex, colIndex };
    }

    // Tried on every conflicting attempt, before falling back to the row-
    // shift below: resolves the specific "short sibling shares a rank
    // with its own divergence point's real destination" shape the
    // row-shift approach can never fix on its own, since it moves an
    // offending node's own same-rank sibling down by the exact same
    // amount every time (see attemptFanoutRelayer's own comment) -- a
    // real, provably-safe lever for that one shape, not a substitute for
    // the row-shift loop otherwise: a no-op (returns null, `graph` left
    // untouched) for a conflict outside that exact shape, so the row-
    // shift fallback below still runs unchanged for anything this can't
    // help. A real corpus diagram can have more than one independent
    // instance of this shape (e.g. a dense S-box reusing several leaves
    // across several sibling pairs) -- retried here every time a fresh
    // conflict surfaces, not just once, so each gets its own chance.
    const relaid = await attemptFanoutRelayer(graph, meta);
    if (relaid) {
      result = relaid;
      rowIndex = buildBaseRowIndex(result);
      colIndex = buildBaseColIndex(result);
      continue;
    }

    const conflictRow = conflictCell[0];
    const previous = rowIndex;
    rowIndex = (v) => {
      const r = previous(v);
      return r >= conflictRow ? r + 1 : r;
    };
  }
  throw new Error('Could not resolve fan-out routing conflicts after 20 buffer-row insertions.');
}

function buildBaseRowIndex(result) {
  const nodeYs = result.children.map((n) => n.y);
  // Only genuinely intermediate bend points can land in a gap between
  // bands (an edge's own endpoints are always resolved via endpointCell,
  // never through these indices) -- collecting exactly those, and no
  // more, is what keeps a plain direct chain from getting a spurious gap
  // row just because some *other* edge's endpoint coordinate happened to
  // round-trip near a band boundary.
  const middlePoints = result.edges.flatMap((e) => pointsOf(e).slice(1, -1));
  return buildAxisIndex(nodeYs, [...nodeYs, ...middlePoints.map((p) => p.y)]);
}

function buildBaseColIndex(result) {
  const nodeXs = result.children.map((n) => n.x);
  const middlePoints = result.edges.flatMap((e) => pointsOf(e).slice(1, -1));
  return buildAxisIndex(nodeXs, [...nodeXs, ...middlePoints.map((p) => p.x)]);
}

// ---------------------------------------------------------- column-reuse --
// 'column-reuse' strategy only. ELK gives each rank's own nodes their own
// column based on its own crossing-minimization heuristic, with no notion
// that a column freed up further down (once whatever was routed through it
// higher up is behind it) could be reused instead of ELK handing out a
// fresh one -- confirmed directly against a real hand-drawn example
// (alternating_feistel_alternative2: the original reuses round 1's `F`
// column for round 2's `xor` once F's own row is passed; ELK's own
// resynthesis instead permanently detours that path into its own 4th
// column). This is a post-process compaction pass over `planPlacement`'s
// already-resolved nodeCell/groups (mirrors alignDeclaredOutputs' own
// "run ELK naturally first, then a small grid-level pass" pattern, proven
// safer here than trying to get ELK's own optimizer to do it) -- it never
// touches ELK's coordinates or `buildElkGraph` at all.
//
// Measured, honest result against the real corpus (all 77 real diagrams):
// 0 regressions (byte-for-byte identical exact/equivalent/failed sets to
// 'arg0', confirmed via verify-pseudocode.mjs) but also 0 files where it
// actually found a mergeable pair -- including the very example that
// motivated it. Root-caused, not just observed: on that example,
// `alternating_feistel_alternative2`'s own hand-drawn column reuse relies
// on round 2's `xor` treating `input[2]` as its own vertical/trunk
// argument (matching round 1's `xor` treating `input[1]` as its trunk) --
// but `buildElkGraph`'s `riskyShare` guard blocks exactly that flip here
// (`input[2]` is reachable from `F'(output[1])`'s own subtree), so round
// 2 ends up trunk-fed by `F'` instead, a genuinely different topology with
// no column to reuse. Reaching the hand-drawn shape would mean loosening
// `riskyShare` or otherwise changing `buildElkGraph`'s own vIdx choice --
// exactly the kind of change this pass was deliberately kept separate
// from (see above), and not attempted here given this exact guard exists
// to prevent a real, previously-hit crash. This pass is shipped as-is: a
// safe, always-available, zero-regression building block for a real
// column-reuse opportunity whenever one exists, not (yet) a fix for this
// specific motivating case.

// Every column actually in use, across every node cell and every routed
// path cell.
function usedColumns(nodeCell, groups) {
  const cols = new Set();
  for (const [, col] of nodeCell.values()) cols.add(col);
  for (const cells of groups.values()) for (const path of cells) for (const [, col] of path) cols.add(col);
  return [...cols].sort((a, b) => a - b);
}

// Collapses column `from` into column `into` (`from` must be strictly
// greater than `into`), shifting every column to the right of `from` left
// by one to close the gap -- a pure data transform, no validation here
// (see tryDraw below for that).
function remapColumns(nodeCell, groups, from, into) {
  const shift = (col) => (col === from ? into : col > from ? col - 1 : col);
  const newNodeCell = new Map([...nodeCell].map(([id, [row, col]]) => [id, [row, shift(col)]]));
  const newGroups = new Map([...groups].map(([key, paths]) => [key, paths.map((path) => path.map(([row, col]) => [row, shift(col)]))]));
  return { nodeCell: newNodeCell, groups: newGroups };
}

// Actually draws `nodeCell`/`groups` into a throwaway Grid, reusing the
// exact same collision-detection this file's real drawing pass already
// relies on (drawFanoutGroup -> drawRouteCell -> mergedCrossBlock) rather
// than re-implementing a parallel validator -- a candidate column merge is
// accepted only if this succeeds without throwing. Deliberately not a
// "virtual"/scratch-only check like alignDeclaredOutputs' planRouteCell:
// unlike a single realignment row, a column merge can perturb routing
// anywhere in the diagram, so reusing the real drawing code end to end is
// the more trustworthy bar, at the cost of materializing (and discarding)
// a real Grid per candidate.
function tryDraw(childIds, nodeCell, groups, meta) {
  const grid = new Grid();
  for (const id of childIds) {
    const [row, col] = nodeCell.get(id);
    grid.placeBlock(row, col, meta.get(id).type, meta.get(id).params);
  }
  const drawn = new Set();
  const reserved = collectDivergenceCells(groups);
  for (const [ref, cells] of groups) drawFanoutGroup(cells, grid, drawn, { reserved, groupRef: ref });
  return grid;
}

// Greedily collapses the leftmost pair of columns that can actually be
// merged, re-validating every candidate by actually drawing the whole
// result (see tryDraw above) and keeping only merges that succeed --
// deliberately no pre-filter trying to predict *which* pairs are safe
// (e.g. by each column's own occupied row range): tried that first and
// it was too conservative to find real opportunities, since a single
// lateral/fan-out routing line spanning several columns in one row makes
// all of them look "occupied" at that row even though the line itself
// isn't a permanent occupant of any one of them -- the real drawing code
// is the only thing that actually knows whether a merge collides.
// Bounded at 20 iterations, matching planPlacement's own backstop --
// not expected to ever actually hit it either.
function compactColumns(childIds, meta, nodeCell, groups) {
  let current = { nodeCell, groups };
  for (let attempt = 0; attempt < 20; attempt++) {
    const cols = usedColumns(current.nodeCell, current.groups);
    let merged = false;
    outer: for (let i = 0; i < cols.length; i++) {
      for (let j = i + 1; j < cols.length; j++) {
        const candidate = remapColumns(current.nodeCell, current.groups, cols[j], cols[i]);
        try {
          tryDraw(childIds, candidate.nodeCell, candidate.groups, meta);
        } catch {
          continue; // this specific merge isn't drawable -- try the next pair
        }
        current = candidate;
        merged = true;
        break outer;
      }
    }
    if (!merged) return current;
  }
  return current;
}

// -------------------------------------------------------- straight-trunk --
// 'straight-trunk' strategy only. When a 2-argument call's lateral
// argument is a value reused elsewhere in the graph (e.g. a key input fed
// into two different XORs), buildElkGraph's own riskyShare guard (for
// good, separate reasons -- see its own comment) refuses to flip that
// argument's vertical/lateral role, which means the REUSED value stays
// the node's recorded "vertical" argument by convention -- while the
// actual computed chain a human would call "the trunk" ends up lateral
// instead, and ELK is then free to drift that node's column sideways to
// match wherever the reused value's own column ends up, producing a long
// detour wire (confirmed directly: even_mansour_single_sbox[rounds=1,
// key=single]'s own output ends up under the *key's* column instead of
// the message's own). This identifies that "trunk predecessor" (the
// OTHER, non-reused argument) independently of vIdx/canFlip/riskyShare
// -- which pick port sides for a different, already-settled reason and
// are deliberately left untouched -- then tries to pull each such node
// back onto its predecessor's column, keeping the change only when the
// whole result still draws cleanly (see tryDraw), exactly like
// compactColumns' own "full redraw, discard on failure" discipline. Any
// relocation must also pass the same checkConnectivity bar
// pseudocodeToGrid's own final result is held to, not just tryDraw's own
// collision detection -- confirmed necessary directly: a relocation
// existed that drew without throwing but left the diagram genuinely
// disconnected (a multiblockpermutation whose neighbor wire expected an
// input it didn't provide).
//
// Measured, honest result against the real corpus (all 77 real
// diagrams, same rigor as column-reuse's own note below): 0 regressions
// (best-of is byte-for-byte identical to without this strategy) but also
// 0 files where a relocation actually validates and changes anything --
// including even_mansour_single_sbox itself, the motivating case.
// Root-caused, not just observed: the reused leaf that pushed the trunk
// off its own column in the first place almost always ALSO fans out to
// a second consumer at some other row, and once the trunk node is pulled
// back, drawFanoutGroup can't route that fan-out's two branches when
// their destinations end up sharing a column (confirmed directly on the
// motivating case: "Fan-out divergence... needs a non-lateral branch
// mid-chain -- unsupported shape", the exact class of gap this file's
// own riskyShare/findAdjacentFanoutConflict comments already document as
// a real, separately-tracked drawing-vocabulary limitation). Reaching
// the hand-drawn shape here would mean extending drawFanoutGroup itself
// to route two same-column fan-out destinations, exactly the kind of
// deeper drawing-engine work this pass was deliberately kept separate
// from. Shipped as-is anyway, matching this file's own precedent
// (column-reuse): a safe, always-available, zero-regression building
// block ready to help the moment that drawing-engine gap closes, not
// (yet) a fix for the motivating case itself.
//
// Graph-wide use count per GraphNode -- how many times it's referenced,
// whether as a call argument or as a target's own direct value (e.g.
// `output[2] = input[2]`, no call at all -- a real, distinct use just as
// much as an argument position is). Mirrors safeWordGroups' own bump/
// visit shape, with one fix safeWordGroups doesn't need: a node's own
// CHILDREN must only ever be recursed into once (the `seen` guard below),
// not once per path that reaches the node itself -- without it, a value
// referenced twice via two different 'index' nodes into the SAME shared
// multi-word tuple (e.g. `output[1] = mixcolumn1[1]; output[2] =
// mixcolumn1[2]`, both indexing the one `mixcolumn1` call) silently
// re-visits and re-bumps everything *underneath* mixcolumn1 a second
// time, inflating the use count of leaves that only actually appear once
// in the pseudocode. Confirmed as a real bug, not a hypothetical: this
// exact shape (even_mansour_double_sbox_mixcolumn) caused canFlip's own
// whole-graph-reuse check (see below) to wrongly treat a single-use
// input as reused, changing its vertical/lateral choice and regressing a
// previously-working file. safeWordGroups itself doesn't need this fix --
// an inflated count there only makes it MORE conservative (refuses to
// share a word-group that would actually have been safe), never unsafe --
// but this function's own callers (canFlip's guard, computeTrunkPredOf)
// treat an inflated count as an active signal to change behavior, so it
// must be exact here.
// True the moment any leaf reachable from targetOrder is declared secret
// (a plain leaf's `.secret`, or a word-group leaf's `.groupSecret`) --
// used to gate buildElkGraph's inputOrderHint so it only ever nudges
// input order for constructions that actually mix public and secret
// inputs (the only shape the "public left, secret right" rule is even
// about). Confirmed necessary, not just cautious: applying the hint
// unconditionally to every diagram (even ones with no secret input at
// all) measurably regressed several unrelated Feistel constructions on
// the full corpus -- soft as `elk.position` hints are, they still
// perturb ELK's crossing-minimization choices for graphs that never
// needed any left-right preference in the first place.
function hasSecretInput(targetOrder) {
  const seen = new Set();
  function visit(node) {
    if (seen.has(node)) return false;
    seen.add(node);
    if (node.kind === 'input') return Boolean(node.secret || node.groupSecret);
    if (node.kind === 'call') return node.args.some(visit);
    if (node.kind === 'named') return visit(node.inner);
    if (node.kind === 'index') return visit(node.of);
    return false;
  }
  return targetOrder.some((t) => visit(t.node));
}

function nodeUseCounts(targetOrder) {
  const counts = new Map();
  const seen = new Set();
  const bump = (node) => counts.set(node, (counts.get(node) || 0) + 1);
  function visit(node) {
    if (seen.has(node)) return;
    seen.add(node);
    if (node.kind === 'call') node.args.forEach((arg) => { bump(arg); visit(arg); });
    else if (node.kind === 'named') visit(node.inner);
    else if (node.kind === 'index') visit(node.of);
  }
  for (const t of targetOrder) {
    bump(t.node);
    visit(t.node);
  }
  return (node) => counts.get(node) || 0;
}

// For every 2-argument call where EXACTLY ONE argument is a directly-
// referenced, graph-wide-reused leaf (kind:'input', use count > 1, and
// not itself a word-group member -- see safeWordGroups' own reasoning for
// why a word-grouped leaf needs its own, separate safety treatment, not
// reused here) and the other is not, records that OTHER argument as this
// call's own trunk predecessor. A 1-argument call or 'named' node
// unconditionally records its sole value (no ambiguity). A plain output
// target (not part of a word group) records its own value the same way.
// Silent (no predecessor recorded) for anything else: 0-arg/3+-arg/
// multi-word calls, 'index' nodes, a 2-arg call where both or neither
// argument is a reused leaf, and any word-group member on either side --
// narrower is safer, matching this file's own established discipline
// (see safeWordGroups' own comments on exactly this kind of empirically-
// narrowed safety condition).
function computeTrunkPredOf(targetOrder) {
  const useCount = nodeUseCounts(targetOrder);
  const isReusedLeaf = (node) => node.kind === 'input' && !node.wordGroup && useCount(node) > 1;
  // A word-group member's own column is fixed by its shared, multi-word
  // node (see buildElkGraph's own word-group branch) -- confirmed
  // directly this needs excluding, not just the 2-arg reused-leaf case:
  // a 1-arg call whose sole argument is a word-group member (e.g. two
  // independent `sbox(input[k])` calls, each reading one word of a
  // shared 2-word input) produced a genuinely worse, visually broken
  // result when "straightened" onto that word's own column -- one word
  // of a shared block isn't a free-standing column to align onto.
  const isWordGroupMember = (node) => node.kind === 'input' && Boolean(node.wordGroup);
  const nodePred = new Map(); // GraphNode -> GraphNode
  const outputPred = new Map(); // output target name -> GraphNode
  const seen = new Set();
  function visit(node) {
    if (seen.has(node)) return;
    seen.add(node);
    if (node.kind === 'call') {
      if (!(isMultiWordType(node.typeName) && node.args.length > 1)) {
        if (node.args.length === 1) {
          if (!isWordGroupMember(node.args[0])) nodePred.set(node, node.args[0]);
        } else if (node.args.length === 2) {
          const [a, b] = node.args;
          if (!isWordGroupMember(a) && !isWordGroupMember(b)) {
            const aReused = isReusedLeaf(a);
            const bReused = isReusedLeaf(b);
            if (aReused !== bReused) nodePred.set(node, aReused ? b : a);
          }
        }
      }
      node.args.forEach(visit);
    } else if (node.kind === 'named') {
      if (!isWordGroupMember(node.inner)) nodePred.set(node, node.inner);
      visit(node.inner);
    } else if (node.kind === 'index') {
      visit(node.of);
    }
  }
  for (const t of targetOrder) {
    visit(t.node);
    if (t.isOutput && !t.wordGroup && !isWordGroupMember(t.node)) outputPred.set(t.name, t.node);
  }
  return { nodePred, outputPred };
}

// Resolves computeTrunkPredOf's GraphNode-keyed maps to [childElkId,
// predElkId] pairs via buildElkGraph's own idOf/outputIdByName -- skips
// any pair that doesn't resolve (defensive) or where child and
// predecessor already share an id (nothing to straighten).
function resolveTrunkPredPairs({ nodePred, outputPred }, idOf, outputIdByName) {
  const pairs = [];
  for (const [node, pred] of nodePred) {
    const childId = idOf.get(node);
    const predId = idOf.get(pred);
    if (childId && predId && childId !== predId) pairs.push([childId, predId]);
  }
  for (const [name, pred] of outputPred) {
    const childId = outputIdByName.get(name);
    const predId = idOf.get(pred);
    if (childId && predId && childId !== predId) pairs.push([childId, predId]);
  }
  return pairs;
}

// Tries each [childId, predId] pair in top-to-bottom order (a
// predecessor's own row is always smaller, per the DAG's own layering, so
// its column is already settled by the time its dependent is checked) --
// for each, tentatively overrides childId's column to match predId's
// current column (see computeCellsWith's own columnOverride param, which
// re-derives every affected edge's own cells automatically) and keeps the
// override only if the whole result still draws cleanly (tryDraw, exactly
// compactColumns' own discipline: full redraw, discard on failure, never
// a partial mutation). A rejected pair is left exactly where ELK put it.
function straightenTrunk(result, meta, rowIndex, colIndex, trunkPredPairs) {
  const childIds = result.children.map((n) => n.id);
  let current = computeCellsWith(result, meta, rowIndex, colIndex);
  const columnOverride = new Map();
  const order = [...trunkPredPairs].sort((a, b) => current.nodeCell.get(a[1])[0] - current.nodeCell.get(b[1])[0]);
  for (const [childId, predId] of order) {
    const predCol = current.nodeCell.get(predId)[1];
    const childCol = current.nodeCell.get(childId)[1];
    if (predCol === childCol) continue;
    const candidateOverride = new Map(columnOverride);
    candidateOverride.set(childId, predCol);
    const candidate = computeCellsWith(result, meta, rowIndex, colIndex, candidateOverride);
    try {
      const candidateGrid = tryDraw(childIds, candidate.nodeCell, candidate.groups, meta);
      // tryDraw alone (drawFanoutGroup's own collision detection) isn't a
      // strict enough bar here -- confirmed directly: a relocation existed
      // that drew without throwing but produced a genuinely disconnected
      // diagram (a multiblockpermutation whose neighbor wire expected an
      // input it didn't provide), only caught by the same connectivity
      // check pseudocodeToGrid's own final result is already held to. Any
      // relocation must clear that same bar, not a weaker one.
      if (!checkConnectivity(candidateGrid).wellConnected) throw new Error('relocation leaves the diagram disconnected');
    } catch {
      continue; // this specific relocation isn't drawable -- leave childId where ELK put it
    }
    columnOverride.set(childId, predCol);
    current = candidate;
  }
  return current;
}

export async function layoutToGrid(graph, meta, strategy, trunkContext) {
  const elk = new ELK();
  const result = await elk.layout(graph);
  let { nodeCell, groups, rowIndex, colIndex } = await planPlacement(result, meta, graph);

  if (strategy === 'column-reuse') {
    const childIds = result.children.map((n) => n.id);
    ({ nodeCell, groups } = compactColumns(childIds, meta, nodeCell, groups));
  }

  if (strategy === 'straight-trunk' && trunkContext) {
    const predOf = computeTrunkPredOf(trunkContext.targetOrder);
    const pairs = resolveTrunkPredPairs(predOf, trunkContext.idOf, trunkContext.outputIdByName);
    ({ nodeCell, groups } = straightenTrunk(result, meta, rowIndex, colIndex, pairs));
  }

  // Negotiated (rip-up-and-reroute) drawing, expressed as bounded
  // restart-with-reordering: greedy sequential drawing is order-dependent
  // (an early group's corridor can occupy exactly the cells a later
  // group's split or approach needs, even when a global solution exists --
  // confirmed repeatedly on the dense corpus files). Rather than ripping
  // individual wires out of a live grid (fragile bookkeeping, especially
  // around merged double_wire cells), each round redraws EVERYTHING on a
  // fresh grid with the failing group promoted to just before the group
  // that owns the blocking cell -- the promoted group claims its cells
  // first, and the former blocker's own drawing then negotiates around
  // them with the full reroute machinery. Round 1 uses the original order,
  // so a diagram that drew fine before behaves byte-identically and pays
  // nothing. Bounded by rounds and by a seen-orders set (a repeated order
  // can only repeat the same failure).
  function negotiateDraw(curNodeCell, curGroups) {
    const reserved = collectDivergenceCells(curGroups);
    const approach = collectApproachCells(curGroups);
    let orderedRefs = [...curGroups.keys()];
    const triedOrders = new Set();
    let lastErr = null;
    let lastConflict = null; // { failedRef, cell, blocker } for diagnostics
    for (let round = 0; round < RIPUP_MAX_ROUNDS; round++) {
      const orderKey = orderedRefs.join('|');
      if (triedOrders.has(orderKey)) break;
      triedOrders.add(orderKey);

      const grid = new Grid();
      for (const n of result.children) {
        const [row, col] = curNodeCell.get(n.id);
        const info = meta.get(n.id);
        grid.placeBlock(row, col, info.type, info.params);
      }
      const drawn = new Set();
      const owners = new Map(); // cellKey -> groupRef that first drew there
      let failedRef = null;
      for (const ref of orderedRefs) {
        try {
          // Deep-copy per attempt: the live-detour machinery splices path
          // arrays in place, and each round must start from the pristine
          // quantized paths, not the previous round's mutations.
          const cells = curGroups.get(ref).map((p) => p.map((c) => [c[0], c[1]]));
          drawFanoutGroup(cells, grid, drawn, { reserved, approach, groupRef: ref, owners });
        } catch (e) {
          failedRef = ref;
          lastErr = e;
          break;
        }
      }
      if (!failedRef) return { grid };

      const m = /\[(\d+),\s*(\d+)\]/.exec(lastErr.message);
      const cell = m ? `${m[1]},${m[2]}` : null;
      const blocker = cell ? owners.get(cell) : null;
      lastConflict = { failedRef, cell, blocker };
      const next = orderedRefs.filter((r) => r !== failedRef);
      const blockerIdx = blocker && blocker !== failedRef ? next.indexOf(blocker) : 0;
      next.splice(blockerIdx >= 0 ? blockerIdx : 0, 0, failedRef);
      orderedRefs = next;
    }
    return { err: lastErr, conflict: lastConflict, orders: triedOrders.size };
  }

  // Outer make-room loop: pure reordering can't fix a MUTUAL conflict
  // (whichever group draws second fails -- confirmed on norx_quarterround:
  // orders cycle within 3 attempts because no free corridor exists across
  // the congested band at all). When negotiation exhausts its orders,
  // insert a fresh empty row at the conflict row -- the same rowIndex
  // patch planPlacement's fan-out buffer uses, here triggered by DRAW
  // failures -- recompute every cell path against it, and negotiate again.
  // Skipped for the two post-pass strategies whose nodeCell/groups carry
  // overrides a recompute would silently discard.
  const skipMakeRoom = strategy === 'column-reuse' || strategy === 'straight-trunk';
  let curNodeCell = nodeCell;
  let curGroups = groups;
  let curRowIndex = rowIndex;
  let outcome = null;
  for (let buf = 0; buf <= DRAW_BUFFER_MAX; buf++) {
    outcome = negotiateDraw(curNodeCell, curGroups);
    if (outcome.grid) return { grid: outcome.grid, nodeCell: curNodeCell };
    if (skipMakeRoom || !outcome.conflict?.cell || buf === DRAW_BUFFER_MAX) break;
    const conflictRow = Number(outcome.conflict.cell.split(',')[0]);
    const prev = curRowIndex;
    curRowIndex = (v) => {
      const r = prev(v);
      return r >= conflictRow ? r + 1 : r;
    };
    ({ nodeCell: curNodeCell, groups: curGroups } = computeCellsWith(result, meta, curRowIndex, colIndex));
  }
  // Give-up diagnostics: keep the original message prefix intact (failure
  // bucketing keys off it) and append the minimal conflict evidence.
  if (outcome?.conflict) {
    outcome.err.message += ` -- negotiated routing gave up (${outcome.orders} order(s), ${Math.min(DRAW_BUFFER_MAX, 99)} buffer rows tried); last conflict: group ${outcome.conflict.failedRef} blocked at [${outcome.conflict.cell}] owned by ${outcome.conflict.blocker ?? 'a real node/unknown'}`;
  }
  throw outcome.err;
}

// ------------------------------------------------------ declared-index --
// alignment ("output[i] should line up with input[i]") --------------------

// Recovers a name's trailing numeric index, in either of the two forms
// this codebase's pseudocode actually uses: an explicit bracket (folded
// into the refKey by buildGraph/parseAssignments, e.g. "output[2]") or a
// bare trailing digit run on the identifier itself (e.g. "input2" --
// IDENT_RE in pseudocode.js accepts digits mid/end of an identifier, so
// this is a normal, unbracketed name as far as parsing is concerned).
// Returns null for a name with neither (e.g. plain "output", or a leaf
// with a non-numeric label) -- such names simply never participate in
// this alignment.
function numericIndexOf(name) {
  const bracket = /\[(\d+)\]$/.exec(name);
  if (bracket) return Number(bracket[1]);
  const trailing = /(\d+)$/.exec(name);
  return trailing ? Number(trailing[1]) : null;
}

// Forces each declared-index output onto the same column as the
// same-index input, when the two disagree after ordinary ELK layout --
// e.g. `output[2] = F(input1)` naturally lands output[2] under F's own
// column, but the declared index says it should line up with input2
// instead, which (since F's value has nothing to do with input2) can only
// be shown as a genuine crossing wire.
//
// ELK's own crossing-minimizer is the wrong tool for this: it actively
// *removes* exactly this kind of "deliberately misaligned" placement
// (confirmed by direct experiment -- see project history) since avoiding
// crossings is its whole job. So this is done as a small, structurally
// safe post-process instead, entirely outside ELK: every `output`-kind
// node is provably on the very last row (layerConstraint: 'LAST') with
// nothing below it, so inserting one fresh row directly above that output
// row -- shifting every output down by one -- can never disturb anything
// else in the diagram; the freed row only ever needs to carry each
// output's own final approach, jogged sideways to its target column when
// that differs from where ELK put it. Two or more outputs' jogs can
// legitimately cross each other (or pass straight through an unrelated
// output's own untouched column) in that freed row -- handled by the same
// drawRouteCell collision/merge logic (double_wire) used everywhere else in
// this file.
// Records one path's cell into a purely virtual (grid-free) occupancy map,
// using the exact same "can these two routes share a cell" rule as
// drawRouteCell (mergedCrossBlock) -- but without ever touching the real
// Grid, so a plan that turns out to be unrepresentable partway through can
// simply be discarded instead of needing to undo real mutations. Returns
// false the moment a cell can't accommodate this route (already carries
// two merged routes, or this route can't merge with what's there).
function planRouteCell(virtual, row, col, entry, exit) {
  const key = `${row},${col}`;
  const at = virtual.get(key);
  if (!at) {
    virtual.set(key, [{ entry, exit }]);
    return true;
  }
  if (at.length >= 2) return false;
  if (at.some((r) => r.entry === entry && r.exit === exit)) return true; // identical route, already accounted for
  if (!mergedCrossBlock(at[0], { entry, exit })) return false;
  at.push({ entry, exit });
  return true;
}

function jogCells(oldCol, targetCol) {
  const step = Math.sign(targetCol - oldCol);
  const cols = [oldCol];
  let c = oldCol;
  while (c !== targetCol) {
    c += step;
    cols.push(c);
  }
  return cols.map((col, i) => ({
    col,
    entry: i === 0 ? 'top' : cols[i] > cols[i - 1] ? 'left' : 'right',
    exit: i === cols.length - 1 ? 'bottom' : cols[i + 1] > cols[i] ? 'right' : 'left',
  }));
}

// Two outputs trading places is the common shape this alignment produces
// (`output[i]` wants input[i]'s column, which is naturally some *other*
// output's column instead) -- and when the two columns aren't adjacent, a
// single row of the ordinary double_wire vocabulary can't
// represent it (confirmed by direct construction: whichever cell is
// common to both routes' spans always ends up wanting one straight
// pass-through and one turn at once, and no catalog block represents
// that combination). But this codebase already has a block built for
// exactly this shape regardless of distance, and regardless of count:
// `multiblockpermutation` (see blockCatalog.js) natively supports an
// arbitrary k-way bijection, not just a 2-element swap -- it draws
// whatever it's given as a single row spanned across as many spacer
// word-columns as needed, with *no* port at all at the columns in
// between, so there is nothing there for anything else to conflict with.
//
// Pure (no grid mutation) -- computes the params for one
// `multiblockpermutation` covering every plan in `plans`, or returns null
// when they don't form a genuine bijection (a plan sharing its *source*
// column with another plan, or its *target* column with another plan --
// either means two values genuinely contending for the same cell, which
// no single permutation block can represent). Unlike this function's own
// first draft, activeInputs and activeOutputs are NOT required to be the
// same column set -- resolveMultiblockPermutation (blockCatalog.js)
// already treats them as fully independent word-index lists, and real
// corpus shapes need that: confirmed directly on classical_feistel[
// rounds=1] (`output[1]=input[2]; output[2]=xor(input[1],F(input[2]))`),
// where output[1]'s natural column (2, wherever ELK's own fan-out routing
// happened to land its direct input[2] passthrough) is neither input's
// column at all, and output[2]'s *target* column (input[2]'s own, 1)
// differs from every existing output's source column -- a real 3-column
// relocation, not a same-set permutation, that the stricter same-set
// version above wrongly rejected. Still a strict generalization of the
// old dedicated 2-output case: for two plans mutually trading the same
// two columns, this derives the identical activeInputs/activeOutputs/
// permutation ('0,<last>' / '0,<last>' / '1,0') that dedicated code used
// to hardcode.
function computeColumnPermutationParams(plans) {
  if (plans.length < 2) return null;
  const oldCols = plans.map((p) => p.oldCol);
  const targetCols = plans.map((p) => p.targetCol);
  if (new Set(oldCols).size !== plans.length) return null; // two plans sharing a source column
  if (new Set(targetCols).size !== plans.length) return null; // two plans sharing a target column

  const left = Math.min(...oldCols, ...targetCols);
  const words = Math.max(...oldCols, ...targetCols) - left + 1;
  const sortedOld = [...oldCols].sort((a, b) => a - b);
  const sortedTarget = [...targetCols].sort((a, b) => a - b);
  const targetIdx = new Map(sortedTarget.map((c, i) => [c, i]));
  const byOldCol = new Map(plans.map((p) => [p.oldCol, p]));
  const permutation = sortedOld.map((c) => targetIdx.get(byOldCol.get(c).targetCol)).join(',');

  return {
    left,
    words,
    params: {
      ...defaultParams('multiblockpermutation'),
      permutation,
      words: String(words),
      activeInputs: sortedOld.map((c) => c - left).join(','),
      activeOutputs: sortedTarget.map((c) => c - left).join(','),
    },
  };
}

// Returns a status object describing what it did -- consumed by
// pseudocodeToGrid's own `diagnostics` output (see pseudocode.js) so a
// caller (e.g. generate-library.mjs) can record *why* a diagram's
// input/output columns look the way they do, not just what they are:
//   { outputs, misaligned, realigned, reason }
// `misaligned` is how many declared outputs (by numeric index, e.g.
// `output[2]`) don't naturally land under the same-numbered input's own
// column; `realigned` is whether this pass actually moved them there;
// `reason` is a short human-readable note for the misaligned-but-not-
// realigned and nothing-to-do cases.
export function alignDeclaredOutputs(grid, targetOrder, leaves, idOf, outputIdByName, nodeCell, meta) {
  const outputs = targetOrder.filter((t) => t.isOutput);
  if (outputs.length === 0) return { outputs: 0, misaligned: 0, realigned: false, reason: 'no declared outputs' };

  // Recomputed (cheap, pure) rather than threaded through as a parameter --
  // must agree exactly with buildElkGraph's own decision of which word
  // groups actually got shared, since only a *shared* group's node id
  // resolves to the group's left-edge column (needing the +index offset
  // below); an unsafe group's leaf already got its own independent node
  // (see safeWordGroups), whose nodeCell position is already its real
  // column -- offsetting that too would double-count.
  const shareableWordGroups = safeWordGroups(targetOrder);

  const leafList = [...leaves.values()];
  const rawCandidates = outputs.map((t) => {
    const id = outputIdByName.get(t.name);
    const [row, groupCol] = nodeCell.get(id);
    // Mirrors the same fix on the input-leaf side just below: when this
    // output is itself part of a *shared* word-group node (see
    // buildElkGraph's own output word-group branch), nodeCell gives the
    // group's left-edge column, not this specific output's own -- offset
    // by its word index to reach it.
    const ownWordOffset = t.wordGroup && shareableWordGroups.has(t.wordGroup.groupId) ? t.wordGroup.index : 0;
    const oldCol = groupCol + ownWordOffset;
    const idx = numericIndexOf(t.name);
    // An indexed output (`output[k]`) matches the same-indexed input by
    // number, same as always. A *lone*, unindexed `output` (the common
    // single-output construction shape) has no index to match by -- fall
    // back to the sole non-secret top-level input, mirroring the same
    // "same position" intent for the one case where "position" is
    // unambiguous (exactly one real, public input to align with). Left
    // as oldCol (no-op) when that's ambiguous (0 or 2+ non-secret leaves).
    let matches = null;
    if (idx !== null) matches = leafList.filter((l) => numericIndexOf(l.name) === idx);
    else if (outputs.length === 1) matches = leafList.filter((l) => !l.secret);
    let targetCol = oldCol;
    if (matches && matches.length === 1 && idOf.has(matches[0]) && nodeCell.has(idOf.get(matches[0]))) {
      // A shared word-grouped leaf's own node id resolves to the
      // *group's* left-edge column (see buildElkGraph's shared multi-
      // word input node) -- offset by its word index to reach its own
      // column.
      const wordOffset = matches[0].wordGroup && shareableWordGroups.has(matches[0].wordGroup.groupId) ? matches[0].wordGroup.index : 0;
      targetCol = nodeCell.get(idOf.get(matches[0]))[1] + wordOffset;
    }
    return { id, row, groupCol, ownWordOffset, targetCol };
  });

  // One plan per output WORD (not per block) -- computeColumnPermutationParams
  // below needs per-word granularity to build a correct permutation, since
  // two words of the very same merged block can each want a different
  // target column (see resolvePlacementUnits: they can only ever be
  // *placed* back as one physical block, but the misalignment math itself
  // is still per word).
  const plans = rawCandidates.map((c) => ({
    id: c.id,
    row: c.row,
    wordOffset: c.ownWordOffset,
    oldCol: c.groupCol + c.ownWordOffset,
    targetCol: c.targetCol,
  }));
  const misaligned = plans.filter((p) => p.targetCol !== p.oldCol).length;

  if (misaligned === 0) return { outputs: outputs.length, misaligned: 0, realigned: false, reason: 'already aligned' }; // nothing to realign -- leave the grid untouched

  // Two or more output *words* can be members of the same physical
  // (merged) output block (see buildElkGraph's shared output word-group
  // branch) -- `outputIdByName` resolves every member to the identical
  // node id in that case, and grid.placeBlock/removeBlock only understand
  // ONE physical block at that id's position. Reduces a group of per-word
  // plans sharing an id to one placement unit per id (own left-edge column
  // = `targetCol - wordOffset`), valid only when every member of that id
  // agrees on the same left edge -- a merged block can only move as one
  // rigid piece, so two members wanting different left edges (e.g. the
  // block's own words would need to swap with each other) can't be
  // satisfied by a single placement. Returns null the moment any id
  // disagrees; for the overwhelming common case (one output word per id),
  // this reduces to exactly the original per-output placement.
  function resolvePlacementUnits(plansToPlace) {
    const byId = new Map();
    for (const p of plansToPlace) {
      if (!byId.has(p.id)) byId.set(p.id, []);
      byId.get(p.id).push(p);
    }
    const units = [];
    for (const members of byId.values()) {
      const leftCols = members.map((m) => m.targetCol - m.wordOffset);
      if (!leftCols.every((c) => c === leftCols[0])) return null;
      units.push({ id: members[0].id, leftCol: leftCols[0] });
    }
    return units;
  }

  // Whatever this pass ends up committing must still be a valid,
  // well-connected diagram -- the per-word/per-block realignment math
  // above (and the jog/permutation drawing below) reasons about *this
  // output row's own* geometry, but the row directly above an output can
  // carry more complex pre-existing structure than a single simple wire
  // (e.g. a `double_wire` merging two unrelated routes at the same cell,
  // for a merged word-group whose own crossing is drawn one row up) --
  // removing/relocating the output can leave such a neighbor cell without
  // its expected match. Snapshotting first and validating with the same
  // authoritative `checkConnectivity` pseudocodeToGrid itself uses,
  // rather than re-deriving a bespoke local check, means any realignment
  // this pass can't safely represent is caught and reverted here instead
  // of leaking an invalid diagram out to the caller.
  const snapshot = grid.snapshot();
  function finalizeOrRevert(result) {
    if (checkConnectivity(grid).wellConnected) return result;
    grid.restore(snapshot);
    return { outputs: outputs.length, misaligned, realigned: false, reason: `realignment would break connectivity (${result.reason}) -- reverted to natural placement` };
  }

  const outputRow = plans[0].row; // all `output`-kind nodes share the LAST layer, i.e. one row

  // The common case in practice: two or more outputs each wanting some
  // *other* misaligned output's own column -- e.g. `output[1] = input[2];
  // output[2] = F(input1)`, where output[2]'s value has nothing to do
  // with input2 but must still line up with it, or a genuine k-way
  // permutation layer (e.g. Gimli's own big/small-swap layers). Drawn as
  // a single multiblockpermutation spanning exactly this group's columns
  // (see computeColumnPermutationParams) whenever the misaligned outputs'
  // own columns form a closed bijection -- regardless of how far apart
  // they are or how many there are. An already-aligned output whose own
  // column falls *inside* the span the misaligned group needs is folded
  // in too, as a plain identity entry (own column, both as source and
  // target) -- multiblockpermutation's span has no notion of "skip this
  // one column, something real is already there," so leaving it out
  // entirely would make the wide block collide with it (confirmed
  // directly: this is exactly what chacha_evenround_diagonal_swap.
  // asciiart's own 15-of-16-misaligned shape does -- the one already-
  // aligned output sits in the middle of the other 15's own span).
  // Anything that doesn't reduce to one clean group (a target column
  // outside this group, or a genuine collision with something unrelated
  // still inside the span) falls through to the general single-row jog
  // logic below, which safely no-ops on shapes it can't represent either.
  const misalignedPlans = plans.filter((p) => p.targetCol !== p.oldCol);
  if (misalignedPlans.length >= 2) {
    const spanLeft = Math.min(...misalignedPlans.map((p) => p.oldCol), ...misalignedPlans.map((p) => p.targetCol));
    const spanRight = Math.max(...misalignedPlans.map((p) => p.oldCol), ...misalignedPlans.map((p) => p.targetCol));
    const spanPlans = plans.filter((p) => p.oldCol >= spanLeft && p.oldCol <= spanRight);
    const permComputed = computeColumnPermutationParams(spanPlans);
    const units = permComputed && resolvePlacementUnits(spanPlans);
    if (permComputed && units) {
      const ignoreKeys = new Set(spanPlans.map((p) => Grid.key(outputRow, p.oldCol)));
      if (grid.canPlaceFootprint(outputRow, permComputed.left, permComputed.words, 1, ignoreKeys)) {
        for (const p of spanPlans) grid.removeBlock(outputRow, p.oldCol);
        grid.placeBlock(outputRow, permComputed.left, 'multiblockpermutation', permComputed.params);
        const rowSpan = grid.getBlockAt(outputRow, permComputed.left).rowSpan;
        const finalRow = outputRow + rowSpan;
        for (const u of units) {
          const info = meta.get(u.id);
          grid.placeBlock(finalRow, u.leftCol, info.type, info.params);
          nodeCell.set(u.id, [finalRow, u.leftCol]);
        }
        return finalizeOrRevert({ outputs: outputs.length, misaligned, realigned: true, reason: `${misalignedPlans.length}-way column permutation` });
      }
    }
  }

  // A pair of outputs trading places between two *adjacent* columns (the
  // common case: two outputs, nothing between them) can't be drawn as two
  // independent single-cell jogs -- each one's own turn would need to
  // reuse a side (e.g. both wanting "left" at the same cell) that the
  // other is already using, since there's no cell physically between two
  // adjacent columns for them to pass each other in. That's exactly what
  // this codebase's dedicated `swap` block is for (see blockCatalog.js):
  // a single 2-word unit whose word-0 top-in flows out word-1's bottom
  // and vice versa. Detected and drawn separately, before the general
  // per-column jog logic below (which still handles a longer-distance
  // move, or a swap against a column that isn't the direct partner).
  const remaining = [...plans];
  const swapPairs = [];
  for (let i = 0; i < remaining.length; i++) {
    for (let j = i + 1; j < remaining.length; j++) {
      const a = remaining[i];
      const b = remaining[j];
      if (a.targetCol === b.oldCol && b.targetCol === a.oldCol && Math.abs(a.oldCol - b.oldCol) === 1) {
        swapPairs.push([a, b]);
        remaining.splice(j, 1);
        remaining.splice(i, 1);
        i--;
        break;
      }
    }
  }

  const jogs = remaining.map((p) => ({ p, cells: jogCells(p.oldCol, p.targetCol) }));

  // Validate the *whole* row first, entirely in a scratch map, before
  // touching the real grid. Corpus experience (see project history) is
  // that this index-matching heuristic fires plenty of times where the
  // match is coincidental, not a real "align these" intent (e.g. two
  // unrelated multi-word primitives whose reading-order-assigned
  // input/output numbers happen to line up) -- when that happens, forcing
  // the realignment anyway produces a genuine, unrepresentable wire
  // collision. Falling back to ELK's own (already valid, already
  // correct) natural placement for the whole row is strictly better than
  // either a hard failure or a partially-mutated grid.
  const virtual = new Map();
  const reserve = (col) => virtual.set(`${outputRow},${col}`, [{ entry: 'reserved', exit: 'reserved' }, { entry: 'reserved', exit: 'reserved' }]);
  let ok = true;
  for (const [a, b] of swapPairs) {
    const colMin = Math.min(a.oldCol, b.oldCol);
    if (virtual.has(`${outputRow},${colMin}`) || virtual.has(`${outputRow},${colMin + 1}`)) {
      ok = false;
      break;
    }
    reserve(colMin);
    reserve(colMin + 1);
  }
  if (ok) {
    outer: for (const { cells } of jogs) {
      for (const c of cells) {
        if (!planRouteCell(virtual, outputRow, c.col, c.entry, c.exit)) {
          ok = false;
          break outer;
        }
      }
    }
  }
  const units = resolvePlacementUnits(plans);
  if (!ok || !units) {
    return {
      outputs: outputs.length,
      misaligned,
      realigned: false,
      reason: `unrepresentable as a single-row jog/swap (${plans.length} output(s), ${swapPairs.length} adjacent-swap pair(s)) -- fell back to natural placement`,
    };
  }

  for (const p of plans) grid.removeBlock(outputRow, p.oldCol);
  for (const [a, b] of swapPairs) {
    grid.placeBlock(outputRow, Math.min(a.oldCol, b.oldCol), 'swap', defaultParams('swap'));
  }
  for (const { cells } of jogs) {
    for (const c of cells) drawRouteCell(grid, outputRow, c.col, c.entry, c.exit);
  }
  for (const u of units) {
    const info = meta.get(u.id);
    grid.placeBlock(outputRow + 1, u.leftCol, info.type, info.params);
    nodeCell.set(u.id, [outputRow + 1, u.leftCol]);
  }
  return finalizeOrRevert({ outputs: outputs.length, misaligned, realigned: true, reason: `${swapPairs.length} adjacent swap(s), ${jogs.length} jog(s)` });
}
