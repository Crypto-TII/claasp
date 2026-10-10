What's new in CLAASP v5
=======================

CLAASP v5 broadens the kinds of primitives that can be represented while
making the main Python interface easier to discover and use.

Values are now described by their mathematical domain and shape. A connection
in a primitive graph may carry bits, fixed-width words, binary-field elements,
or prime-field elements. Traditional and arithmetization-oriented primitives
therefore use the same graph model without being forced into an artificial bit
representation.

The implementation is independent of SageMath. Scalar and batch evaluation,
graph construction, intermediate representations, serialization, and source
generation belong to separate layers. External algebra systems and solvers are
optional integrations.

The public interface also distinguishes a primitive description from its
realization, execution strategy, and analysis backend. This makes supported
choices visible, keeps experiments reproducible, and allows the same primitive
to be used in different workflows.

CLAASP v5 is a new major version with a deliberately revised API. Code written
for earlier releases may need to be adapted rather than relying on legacy
names or compatibility aliases.

The following pages introduce these ideas gradually. See :doc:`concepts` for
the common vocabulary and :doc:`parameters` for arithmetization-oriented
primitives and verified parameter sets.
