# ADR 0006: Provide concise cipher-authoring syntax over the typed graph

## Status

Accepted.

## Decision

Components accept either a whole `Port` or a `Selection`; whole ports are
normalized to all logical units. Ports and selections support Python indexing
and slicing. Component identifiers are optional at construction and are
assigned deterministically by `Cipher.add_component` from the component kind,
round, and position. Authors may still supply semantic identifiers.

Component constructors place semantic operands first and the optional
`component_id` keyword last. Cipher outputs likewise accept whole ports. The
explicit `select` and `select_all` methods remain available as lower-level
operations, but ordinary cipher code should not need them.

Generic mathematical helpers belong in public utility modules and are reused
by evaluators and cipher definitions.

Cipher objects provide the ordinary evaluation boundary. Traditional bit,
byte-field, and word vectors accept and return packed integers; callers may
use positional, keyword, or mapping inputs. Prime-field vectors remain tuples
of mathematical elements. `evaluate_with_trace` is the explicit route to raw
logical-unit values and intermediate components.

## Consequences

- Common cipher code follows pseudocode more closely.
- Automatic names remain stable for an unchanged graph.
- Explicit semantic names support analysis and documentation without being
  mandatory boilerplate.
- This intentionally changes the provisional pre-v5 component constructor
  signatures; compatibility shims are not retained.
