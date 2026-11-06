Internal architecture
=====================

CLAASP separates the meaning of a primitive from the mechanisms used to execute
or analyze it.

The typed graph
---------------

Unit types define the semantics of one logical unit, such as a bit, a
fixed-width word, an element of :math:`GF(2^w)`, or an element of
:math:`GF(p)`. ``UnitArrayType`` adds a homogeneous shape. ``UnitArray`` and
``Selection`` connect components using logical units, so a permutation is
reusable without assuming that every unit is a bit.

Components are immutable operation descriptions. They do not evaluate
themselves and do not contain MiniSat-, Z3-, MILP-, or computer-algebra-system
code. A ``Primitive`` validates their directed acyclic graph and round grouping.

The corresponding source packages have deliberately concrete names:

.. code-block:: text

   graph/       Primitive, Component, UnitArray, Round, and UnitArrayType structure
   unit_types/  Bit, Word, GF(2^w), and GF(p) logical unit types
   components/  Operations connecting graph values
   primitives/  Concrete block-cipher and permutation descriptions
   semantics/   What flowing values mean and how transitions behave

In particular, ``semantics`` defines concrete values, differences, masks,
truncated states, symbolic values, and leakage observations. It does not
contain SAT-, SMT-, MILP-, or CP-specific encodings.

Shared propagation
------------------

``claasp.graph.GraphPropagation`` owns the graph schedule and wiring for
propagation-based execution and analysis. Concrete values, continuous bit
vectors, symbolic polynomials and degree bounds use its ``run()`` method.
The same runner also derives affine state and master-key expressions for
circle-linear analysis. Scalar and sample-parallel avalanche measurements
use these execution paths; probability estimates are computed from the
resulting samples rather than assuming independent bit probabilities.

The runner resolves component operands, structural joins and views, bit/word
conversions and the declared primitive output. A component rule receives
only the operation and its selected operands. Representations with different
logical-unit encodings can override packing and unpacking while keeping
the same binding traversal. Validation and trace construction remain
explicit at the representation boundary.

Constraint construction uses the same plan's ``bit_wiring()`` or
``unit_wiring()`` and ``relations()`` methods. These allocate source objects,
resolve every operand and enumerate consumer edges before applying local
relations. Differential, linear, truncated, quasi-differential and
monomial/division-property constructions therefore use the same structural
connections. Each semantic rule still defines its own transition relation,
weights, signs and fanout equations. For example, a concrete value is copied
at fanout, XOR-linear masks combine by XOR, and division-property copies
obey their own constraints. Sharing traversal does not make those laws
interchangeable or turn heuristic continuous values into exact probabilities.

New graph-wide propagation implementations must use this infrastructure
instead of adding another component traversal or structural-binding resolver.
A specialized search may optimize a validated structure derived from the
plan; it must not maintain a parallel specification of a primitive's rounds,
constants or key schedule. Independently checked transition mathematics
remains separate from search encodings. New analyses build a fresh plan so
that changes to a primitive are observed by every execution and analysis path.

Processing vocabulary
---------------------

CLAASP uses four terms for the processing pipeline:

``SemanticType``
   What the values flowing through the graph mean: concrete values, XOR
   differences, linear masks, truncated states, symbolic expressions,
   division properties, or leakage observations.

``Representation``
   The form in which an interpreted graph or problem is expressed: direct
   executable operations, CNF, SMT, MILP, a polynomial system, Python or C
   source, or a diagram IR.

``Driver``
   A mechanism which processes a representation, such as MiniSat, Z3, GLPK,
   GCC, or LaTeX. Direct Python execution is also a driver, but it does
   not need a serializer or external executable.

``Result``
   The semantic outcome returned to the caller: an evaluation result,
   execution trace, cryptanalytic trail, recovered key, solver result, or
   rendered diagram.

An ``Artifact`` is a concrete representation instance such as a DIMACS file,
SMT-LIB program, LP model, C source file, or TikZ document. The word
``target`` is deliberately not used for representations: in analysis it is
reserved for an attack goal such as key recovery, collision, preimage, or
distinguisher construction.

Compilation pipeline
--------------------

Internally, CLAASP uses the following vocabulary:

.. code-block:: text

   typed primitive graph + semantics
       -> lowering       intermediate representation
       -> optimization   equivalent, more suitable representation
       -> export         DIMACS / SMT-LIB / polynomial program
       -> driver         interpreter, solver, compiler, or renderer
       -> projection     typed user-facing result

``Compilation`` names this overall process. ``Lowering`` is the particular
semantics-preserving step from a more abstract graph to a more restricted
representation. Exporting only serializes an already lowered model.

For example, a word-level ``ModularAdd`` remains a single component in a
Speck graph. Boolean lowering expands it into sum and carry constraints; SMT
export writes the resulting assertions as SMT-LIB. Users normally invoke the
complete pipeline through ``primitive.analysis`` and do not call these stages.

Annotations, traces, and trails
-------------------------------

Concrete execution, cryptanalytic propagation, simulated leakage, and
visualization all attach information to unit arrays and components of the same
primitive graph. They therefore share an immutable graph-annotation foundation.
Their public semantic types remain distinct: an ``ExecutionTrace`` records
concrete values, a cryptanalytic ``Trail`` records transitions and weights,
and a ``SideChannelTrace`` records leakage observations. A diagram may consume
any of these annotations without confusing their meanings.

Solver-specific representations do not define trail semantics. For example,
XOR-differential semantics determines component transitions and weights;
SAT, SMT, MILP, and CP representations independently encode that shared
propagation problem.

Correctness boundaries
----------------------

The scalar execution driver is the executable reference. Solver results are
projected back to logical values and independently checked where practical.
Trail results additionally carry transition semantics that can be validated
without trusting the backend which found them.

The graph and semantic layers stay Sage-independent. Optional solvers and algebra systems are
adapters outside the graph, so installing CLAASP does not require every tool.
