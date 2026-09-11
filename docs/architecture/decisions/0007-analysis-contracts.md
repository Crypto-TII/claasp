# ADR 0007: Express analysis constraints over graph values

## Status

Accepted.

## Decision

Public analysis problems use immutable constraints over ports and selections.
They never require encoded SAT, SMT, MILP, or CP variable names. Fixed values,
equality, inequality, nonzero conditions, Hamming-weight bounds, projections,
and weight objectives form the initial shared vocabulary.

`cipher.analyze()` is the user-facing entry point. Backend lowerings consume an
`AnalysisProblem`; backend results are projected back into packed integers or
logical-unit tuples. Results retain status, runtime, backend, model statistics,
raw backend output, and a formula fingerprint.

## Consequences

- A key-recovery call does not expose CNF or DIMACS details.
- Future backends can share problem and result semantics.
- Unsupported objectives or domain/component combinations fail explicitly.
- Raw models and solver results remain available for reproducible research.
