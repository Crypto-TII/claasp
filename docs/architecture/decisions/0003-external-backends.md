# ADR 0003: Keep evaluation and analysis outside components

Status: accepted

## Decision

Components declare operation semantics and typed ports. Evaluators and
analysis backends lower or execute components through registries or visitors.
Components do not accumulate methods for every solver, domain, and runtime
representation.

## Consequences

- Core components do not import Sage, SAT, SMT, MILP, or CP packages.
- Backends advertise supported component/domain combinations.
- A pure-Python scalar evaluator serves as the reference implementation.
- Alternative polynomial presentations can coexist without changing cipher
  descriptions.
