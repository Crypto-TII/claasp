What's new in CLAASP v5
=======================

CLAASP v5 broadens the kinds of primitives that can be represented while
making the main Python interface easier to discover and use.

* **Typed values.** Values are described by their mathematical domain and
  shape. A connection in a primitive graph may carry bits, fixed-width words,
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
