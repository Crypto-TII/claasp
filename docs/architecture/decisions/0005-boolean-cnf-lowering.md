# ADR 0005: Keep Boolean CNF lowering solver-independent

## Status

Accepted.

## Context

CLAASP v5 needs to recover bit-oriented SAT analyses without coupling the
typed graph to a particular solver API. A graph unit may be a bit, word, or
field element, so treating every unit as an implicit Boolean would be
incorrect.

## Decision

`BooleanCNFModel` accepts only graphs whose ports use the `Bit` domain and
lowers supported component semantics into an immutable `CNFFormula`.
Variables retain deterministic graph-derived names and clauses retain their
component provenance. DIMACS serialization is a separate exporter, and solver
execution will be provided by optional adapters.

Components or domains without a defined Boolean lowering raise explicit
errors. Cross-domain bit decomposition must therefore become an explicit
operation before such graphs can enter a Boolean backend.

## Consequences

- The Boolean model and its tests remain Sage- and solver-independent.
- SAT backends can share one audited component lowering.
- Evaluation-derived witnesses directly test lowering correctness.
- Future solver-specific features, such as assumptions and incremental
  solving, do not leak into the core graph or CNF representation.
