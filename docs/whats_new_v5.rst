What's new in CLAASP v5
=======================

CLAASP v5 broadens the kinds of primitives that can be represented while
making the main Python interface easier to discover and use.

* **Typed values.** Values are described by their unit type and shape. A
  connection in a primitive graph may carry bits, fixed-width words,
  binary-field elements, or prime-field elements. Traditional and
  arithmetization-oriented primitives can therefore use the same graph model
  without being forced into an artificial bit representation.
* **Ordinary Python.** The core implementation is independent of SageMath and
  runs on CPython. External algebra systems and solvers are optional
  integrations.
* **Separate layers.** Graph construction, evaluation, intermediate
  representations, serialization, and source generation have distinct roles.
  A primitive can be reused across these workflows instead of being
  implemented separately for each one.
* **Explicit choices.** The public interface distinguishes a primitive
  description from its realization, execution strategy, and analysis backend.
  Supported choices are visible and experiments are easier to reproduce.
* **Revised API.** CLAASP v5 is a new major version with a deliberately revised
  interface. Code written for earlier releases may need to be adapted rather
  than relying on legacy names or compatibility aliases.

The following pages introduce these ideas gradually. See :doc:`concepts` for
the common vocabulary and :doc:`parameters` for arithmetization-oriented
primitives and verified parameter sets.

Explicit propagation names
--------------------------

Propagation model names identify the difference or mask semantics explicitly.
For example, use ``WordXorDifferentialSATModel`` and
``WordXorLinearSATModel``; SMT, MILP and CP use the same convention.
Composed models use ``XorDifferentialLinear``, as in
``WordDeterministicXorDifferentialLinearSATModel``. XOR refers to the
difference definition or parity checks, even when the primitive contains
modular addition. It does not assert that the primitive itself is linear.

Circle-linear trail search uses ``CircleLinearTrailModel`` and
``primitive.analysis.circle_linear_trail_model(...)``. The current backend
is reported as ``perfect_subgroup_spn`` and its result states the restricted
search scope. Endpoint correlations remain available through
``primitive.analysis.circle_linear(...)``. These are direct API renames;
the earlier v5 spellings are not retained as aliases. Update imports and
call sites when moving from an earlier v5 checkout.

The user guide's **Trail search and verification** group now separates search guides from
characteristic validation, concrete realizability and actual endpoint
probability/correlation evaluation. Each Verification page states the
capabilities currently available for its analysis.

Circle differentials
--------------------

``primitive.analysis.circle_differential(...)`` measures alternative-difference
probabilities through the standard evaluator. It supplies exact circle-DDTs
using the shared XOR-DDT semantics, bounded concrete-trail search, and exact or
sampled endpoint and trail verification at explicitly fixed keys and tweaks.
Reported trail factors are conditioned on actual preceding events. The module
does not add a solver-based circle-differential characteristic backend or
assume that independent local DDT probabilities give a fixed-key trail's
probability. Basic, Advanced and Verification guides are available in the
**Trail search and verification** group.
