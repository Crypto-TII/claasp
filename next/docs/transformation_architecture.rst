Transformation architecture
===========================

Graph transformations are pure reconstruction passes. They consume a
validated :class:`~claasp_next.graph.Primitive`, traverse immutable typed
sources, and return a newly validated primitive. They never expose or recreate
the legacy mutable editor, round dictionaries, or generated component-id
protocols.

Core invariants
---------------

Every transformation preserves these boundaries:

* semantic operations remain
  :class:`~claasp_next.graph.Component` objects;
* reusable hierarchy remains a composite scope overlay;
* joins, ordered views, ``PackBits``, and ``UnpackBits`` remain structural
  bindings;
* realization identity identifies the chosen source construction, while
  :class:`~claasp_next.provenance.TransformationRecord` records graph
  derivation and execution provenance records the eventual engine; and
* reconstruction validates source membership, logical-unit positions, domain
  equality, acyclicity, and output availability through the ordinary graph
  API.

An explicitly authored ``Identity`` component remains semantic. A
transformation must not invent one as a wiring placeholder.

Dependency closure and slicing
------------------------------

:class:`~claasp_next.transformations.DependencyIndex` indexes primitive
inputs, semantic components, structural bindings, and composite membership.
Traversal order is deterministic but is not a public component-id or mutable
list-order contract.

Slicing walks backward from an output until it reaches original inputs or an
explicit boundary. Every required logical unit must be present. Forward and
backward split closures are inclusive, and an incomplete boundary fails with
``disconnected_dependency``. Complete composite scopes can be retained as
hierarchy overlays; a partial scope is flattened rather than falsely presented
as a complete reusable instance.

Inverse semantics
-----------------

:class:`~claasp_next.transformations.ComponentInverseRegistry` is an immutable,
exact-type registry. A rule receives a known component output, the predecessor
index to recover, and every other predecessor as an auxiliary value. It returns
an unowned semantic component, which the destination graph assigns an identity.
Extensions use
:meth:`~claasp_next.transformations.ComponentInverseRegistry.with_semantics` to
create a new registry instead of changing global process state.

Complete inversion starts with the primitive output and retained inputs.
Partial inversion starts with arbitrary explicit known boundaries. Structural
binding equivalences propagate in both directions; semantic components are
forward-built when all predecessors are known and reversed only when exactly
one predecessor remains unknown. Equivalent recovered wires share the same
selection.

Failure diagnostics are stable contracts:

``unsupported_component``
   No graph-native inverse rule represents the required semantics.
``information_loss``
   The operation is non-bijective for the requested recovery.
``multiple_predecessors``
   More than one predecessor remains unknown.
``missing_auxiliary_value``
   A selected recovery omitted another required predecessor.
``ambiguous_boundary``
   A boundary index, type, width, or partial predecessor is ambiguous.
``disconnected_dependency``
   Known boundaries cannot reach every requested target wire.

No inverse is claimed for a lossy operation without retained information or a
typed partial-recovery contract. These rules are solver-independent.

Editor and paired transformations
---------------------------------

Round reduction uses published round-state boundaries. Key-schedule removal
classifies sources by their primitive-input dependencies. Retained injection
sites become explicit secret round-key inputs; removing injections is limited
to recognized zero-neutral operations. Reorder inlining accepts only exact
logical permutations, permutation matrices, and fixed word rotations. It emits
views and bit packing bindings, leaving non-permutation linear maps semantic.

Paired XOR construction instantiates the source definition twice under
``left`` and ``right`` composite scopes. Shared inputs bind both scopes to one
port. Characteristic-two differences are ordinary semantic XOR/addition
components over input, published round-state, round-key, and output boundaries.
Domains without XOR semantics fail explicitly.

Validation evidence
-------------------

Transformation tests compare independently evaluated values, fixed primitive
vectors, exhaustive small component domains, and fixed compatible/incompatible
paired Speck constraints. Structural equality alone is not evidence of
semantic correctness. Ordinary unit cases remain sub-second; external solver
checks are isolated and marked explicitly.
