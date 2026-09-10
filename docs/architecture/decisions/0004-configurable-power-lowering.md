# ADR 0004: Make power lowering explicit and configurable

Status: accepted

## Decision

Prime-field polynomial models expose a power-lowering policy. `direct` emits
one equation containing the original exponent. `binary_chain` introduces
deterministically named auxiliary power variables and equations of degree at
most two. The cipher graph and scalar evaluator are unchanged by this choice.

Polynomial models can construct a complete witness, including auxiliary
variables, from a scalar evaluation result. Equation provenance records both
the originating component and the represented exponent.

## Consequences

- Solver experiments can trade fewer variables for lower equation degree.
- Exporters remain independent of lowering strategy.
- Auxiliary names form part of deterministic model output, not cipher APIs.
- Future addition-chain optimizers can become new policies without changing
  components or silently altering existing experiments.
