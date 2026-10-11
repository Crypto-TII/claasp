// Orchestrator for the integrated human-drawing strategy.  It receives the
// expression graph already built by pseudocode.js, tries reusable semantic
// circuit-family layouts first, and then uses the general slot-based engine.
// Keeping parsing outside this module avoids a pseudocode.js import cycle and
// lets semantic-auto rebuild an untouched graph before falling back to ELK.
import { checkConnectivity } from '../../../connectivity.js';
import { buildSemanticLayoutCandidates } from '../../../semanticLayout.js';
import { detectSwapPairs } from './engine.js';
import { buildGrid } from './wiring.js';

export function graphToGridHumanDrawing(targetOrder, { diagnostics, ...options } = {}) {
  const { plan, candidates } = buildSemanticLayoutCandidates(targetOrder);
  if (candidates.length > 0) {
    const winner = candidates[0];
    if (diagnostics) Object.assign(diagnostics, {
      engine: 'semantic-pattern',
      alignment: { outputs: plan.outputCount, misaligned: 0, realigned: false, reason: 'semantic layout preserves inferred state lanes' },
      semantic: {
        matched: true,
        pattern: plan.kind,
        ...(plan.groupSize === undefined ? {} : { groupSize: plan.groupSize }),
        groups: Array.isArray(plan.groups) ? plan.groups.length : (plan.groups ?? 1),
        candidate: winner.name,
        score: winner.score,
        metrics: winner.metrics,
      },
    });
    return winner.grid;
  }

  if (diagnostics) diagnostics.semantic = { matched: false };
  detectSwapPairs(targetOrder);

  const grid = buildGrid(targetOrder, options);

  const connectivity = checkConnectivity(grid);
  if (!connectivity.wellConnected) {
    const first = connectivity.problems[0];
    throw new Error(`Routing produced an invalid diagram (${first.message}).`);
  }
  if (diagnostics) Object.assign(diagnostics, {
    engine: 'human-drawing',
    alignment: { outputs: targetOrder.filter((target) => target.isOutput).length, misaligned: 0, realigned: false, reason: 'slot layout owns output placement' },
  });
  return grid;
}
