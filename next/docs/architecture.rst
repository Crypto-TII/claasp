Internal architecture
=====================

CLAASP separates the meaning of a cipher from the mechanisms used to execute
or analyze it.

The typed graph
---------------

Domains define scalar semantics such as a bit, a fixed-width word, an element
of :math:`GF(2^w)`, or an element of :math:`GF(p)`. ``ValueType`` adds a
homogeneous shape. Ports and selections connect components using logical
units, so a permutation is reusable without assuming that every unit is a
bit.

Components are immutable operation descriptions. They do not evaluate
themselves and do not contain MiniSat-, Z3-, MILP-, or computer-algebra-system
code. A ``Cipher`` validates their directed acyclic graph and round grouping.

Compilation pipeline
--------------------

Internally, CLAASP uses the following vocabulary:

.. code-block:: text

   typed cipher graph
       -> lowering       backend intermediate representation
       -> optimization   equivalent, more suitable representation
       -> export         DIMACS / SMT-LIB / polynomial program
       -> execution      evaluator, solver, or external tool
       -> projection     typed user-facing result

``Compilation`` names this overall process. ``Lowering`` is the particular
semantics-preserving step from a more abstract graph to a more restricted
backend representation. Exporting only serializes an already lowered model.

For example, a word-level ``ModularAdd`` remains a single component in a
Speck graph. Boolean lowering expands it into sum and carry constraints; SMT
export writes the resulting assertions as SMT-LIB. Users normally invoke the
complete pipeline through ``cipher.analyze()`` and do not call these stages.

Correctness boundaries
----------------------

The scalar evaluator is the executable reference. Solver results are
projected back to logical values and independently checked where practical.
Trail results additionally carry transition semantics that can be validated
without trusting the backend which found them.

The core stays Sage-independent. Optional solvers and algebra systems are
adapters outside the graph, so installing CLAASP does not require every tool.
