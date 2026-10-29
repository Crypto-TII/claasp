Boolean polynomial systems and algebraic tests: advanced
========================================================

Retaining local equations
--------------------------

``polynomial_system()`` supports Bit/Word wiring, Boolean operations, lookup
substitutions and modular addition/subtraction. It retains intermediate
variables and explicit ripple carries rather than expanding the full cipher.
Unsupported components raise an error instead of omitting constraints.

.. code-block:: python

   from claasp.primitives import Speck

   result = Speck(number_of_rounds=7).analysis.polynomial_system()
   result.to_terminal()                    # cumulative statistics
   result.to_terminal(cumulative=False)    # each round separately

``result.system`` retains equations, round ownership, registered variables,
input-variable names, and output polynomials. All bit positions are MSB first.
Each equation is interpreted as zero and variables take values in {0, 1}.

Connection graphs
------------------

A small substitution illustrates which variables occur together in equations:

.. plot::
   :include-source: True

   from claasp.primitives import BitVectorSBox

   toy = BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system()
   graph = toy.connection_graph()
   graph.plot()

The graph is bipartite: one set contains variables, the other equations.
An edge means a variable occurs in an equation. The graph retains its nodes
and edges independently of the optional plotting dependency. For a larger
primitive, select ``result.connection_graph(round_number=1)``. Layout is
limited to 2,000 nodes; statistics and equation construction have no such
plotting limit. Use ``plot(show=False, save_to="connections.png")`` to export.

Bounded Gröbner computations
----------------------------

Install the optional Singular executable, then compute a small example:

.. code-block:: python

   basis = toy.groebner(timeout_seconds=5)
   basis.require_complete()
   print(basis.basis)

The exported ideal includes the field equations ``v_i**2 + v_i = 0``. A
completed basis is reported in Singular notation over GF(2), with the
registered ``v0``, ``v1``, ... names. To add Boolean assignments, pass
``fixed_variables={"v0": 0, "v1": 0}``. Input names are recorded in
``toy.system.inputs``; output variables occur in ``toy.system.outputs``.
A completed basis ``("1",)`` proves the specified equations inconsistent.

The time limit applies to the external computation. If it expires,
``complete`` is false, the basis is empty, and ``require_complete()`` raises.
A timeout is not evidence that no solution exists, nor a security result.
Even local systems can have expensive Gröbner bases; begin with few rounds or
a small primitive and set a practical limit. ``system.singular_program()``
exports the same ideal for separate inspection or execution.
