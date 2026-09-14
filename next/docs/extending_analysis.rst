Extending cryptanalysis
=======================

CLAASP is both an analysis library and an experimentation platform for
cryptography researchers. Adding a new attack or testing a new component
model should not require forking an entire backend.

Current extension boundaries
----------------------------

The typed graph, backend-neutral ``AnalysisProblem``, graph-level
constraints, trail semantics, backend representations, exporters, solver
adapters, and result projection are separate layers. New work should extend
the narrowest applicable layer.

The architectural vocabulary is ``SemanticType -> Representation -> Driver
-> Result``. A new cryptanalytic idea normally begins as a semantic type or
shared propagation relation. Encoding it directly inside an SMT- or
MILP-specific package is appropriate only when it is genuinely specific to
that representation. An alternative external solver for an existing format
is a driver, not a new semantic type.

Examples include:

* adding a new graph-level constraint without exposing encoded variable names;
* registering an alternative S-box transition encoding;
* adding or replacing constraints for one component in a full primitive model;
* transforming a lowered model before export;
* implementing another solver adapter for an existing representation; and
* attaching an independent checker or renderer to a result.

Research API requirement
------------------------

The full plug-in API has not yet been finalized. Before CLAASP 5 stabilizes,
we will separately design and review researcher workflows for:

* adding, removing, replacing, and inspecting model constraints;
* selecting a component-model strategy globally or for individual graph
  components;
* composing custom objectives, bounds, assumptions, and blocking clauses;
* retaining provenance when a model is transformed;
* validating experimental results independently; and
* packaging an experimental technique without modifying CLAASP internals.

This is a product requirement, not merely a possible implementation detail.
Until that review is complete, internal IR constructors should not be treated
as a stable plug-in interface. The existing graph-level constraint API is the
first supported portion of this direction.

Canonical trail semantics
-------------------------

Exact patterns, transitions, weights, correlations, and trails are defined in
``claasp_next.semantics.cryptanalysis``. Constraint representations may
encode these objects but must not redefine their mathematical meaning. The
``claasp_next.analysis`` package re-exports common trail types as a concise
user facade; representation code uses the canonical semantics package.

Propagation problems and component overrides
--------------------------------------------

``PropagationProblem`` selects a primitive, semantics, component scope,
objective, optional weight bound, semantic registry, and provenance before a
SAT, SMT, MILP, or CP representation is chosen:

.. doctest::

   >>> from claasp_next.primitives import Present
   >>> from claasp_next.components import BitVectorSBox
   >>> from claasp_next.semantics import XOR_DIFFERENTIAL
   >>> from claasp_next.semantics.cryptanalysis import PropagationProblem
   >>> primitive = Present(number_of_rounds=1)
   >>> sbox = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
   >>> problem = PropagationProblem(primitive, XOR_DIFFERENTIAL, component_ids=(sbox.component_id,), maximum_weight=4, provenance=("experiment-1",))
   >>> problem.provider_for(sbox).transition((1,), 3).weight
   2.0

The registry is immutable. ``registry.register(binding)`` returns a new
registry, and a binding with ``component_id=...`` overrides a global binding
only for that graph component. This is the first concrete researcher API for
plugging a new component model into a full propagation problem without
editing a solver representation.
