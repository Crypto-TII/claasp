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

The architectural vocabulary is ``Interpretation -> Representation -> Driver
-> Result``. A new cryptanalytic idea normally begins as an interpretation or
shared propagation relation. Encoding it directly inside an SMT- or
MILP-specific package is appropriate only when it is genuinely specific to
that representation. An alternative external solver for an existing format
is a driver, not a new interpretation.

Examples include:

* adding a new graph-level constraint without exposing encoded variable names;
* registering an alternative S-box transition encoding;
* adding or replacing constraints for one component in a full cipher model;
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
