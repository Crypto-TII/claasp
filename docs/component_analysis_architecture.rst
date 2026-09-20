Component-analysis architecture
===============================

Contracts and boundaries
------------------------

``PropertyRequest`` combines a ``ComponentProperty``, a ``PropertyDomain``,
and immutable named options. ``ComponentPropertyResult`` combines an immutable
value with a ``PropertyClaim``, completeness, provenance, and—only for an
unavailable result—a typed ``PropertyDiagnostic``. Exact values require proved
complete coverage. Proved lower and upper bounds, empirical observations, and
unavailable results remain distinct machine-readable claims.

The analysis operates on semantic components. Composite scopes define reusable
graph structure; bindings define wiring and views; realizations select an
implementation; representations lower graphs; analyses derive facts; and
drivers execute optional computations. Concatenation, ordered views, PackBits,
and UnpackBits are bindings and never enter semantic discovery.

Grouping and provenance
-----------------------

``semantic_component_groups`` keys operations by concrete component type,
typed input/output value types, immutable semantic parameters, and requested
domain. It does not key by component id, description text, or traversal order.
Stable round/component locations may appear only as evidence references.

Analysis provenance records semantic identity, method, primitive family,
realization, and optional graph locations. Driver identity is a separate field,
so using MiniZinc or bounded enumeration cannot overwrite the realization or
mathematical method that produced the request.

Applicability and validation
----------------------------

The dispatcher defines supported property/domain combinations for lookup
tables, linear maps, Boolean word operations, and feedback registers.
Unsupported components, properties, domains, unavailable drivers, and exhausted
budgets return stable diagnostics. Invalid lookup ranges, dimensions, value
types, matrices, register terms, and field definitions are rejected at typed
construction boundaries rather than converted into plausible-looking values.

Matrices are row-major and act on column vectors. Binary-extension fields use
the domain's explicit irreducible modulus and polynomial-basis encoding. Word
differentials use the declared matrix; linear masks use the transpose. Bit
expansion preserves the same MSB-first unit and polynomial-basis conventions.
Lookup ANFs, DDTs, LATs, BCTs, Boolean symbolic polynomials, and field/matrix
utilities reuse the existing v5 semantic layers.

Exactness rules
---------------

Small lookup and algebra calculations are dependency-free and exhaustive.
Branch enumeration is exact only when every nonzero input is covered or a
proved lower bound is attained. An incomplete support search is a proved upper
bound on a minimum, not an exact result. Solver-backed optimization is exact
only after the driver observes successful optimal termination. Limits produce
``budget_exhausted`` rather than silent truncation.

Extension points
----------------

To add a property, first extend the typed enums and define its component/domain
applicability. Implement a dependency-free analyzer when complete small
calculation is practical; otherwise implement ``ComponentPropertyDriver``.
Both paths consume the same request and return the same result contract. Add
independent fixed evidence, exhaustive reduced-width checks, conservative
catalogue capability metadata, public docstrings, and doctests. Do not add
plotting, mutable report dictionaries, implicit solver selection, or backend
variable spellings to the component-analysis layer.
