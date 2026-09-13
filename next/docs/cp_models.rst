Constraint-programming representations
======================================

M10.6a introduces the Sage-independent CP foundation. ``MiniZincModel`` is a
small immutable representation that owns MiniZinc language items; external
process execution belongs to ``MiniZincSolver`` under ``drivers``. Neither the
core graph nor the representation imports the MiniZinc Python package.

.. doctest::

   >>> from claasp_next.representations.constraints.cp import MiniZincModel
   >>> model = MiniZincModel(
   ...     declarations=("var 0..3: x;",),
   ...     constraints=("constraint x = 2;",),
   ...     provenance=("documentation example",),
   ... )
   >>> print(model.source())
   var 0..3: x;
   constraint x = 2;
   solve satisfy;
   <BLANKLINE>

The optional command-line driver requests MiniZinc's JSON output mode and
returns named logical values in ``CPResult``. For example, on a machine with
MiniZinc and Gecode installed:

.. code-block:: python

   from claasp_next.drivers.solvers import MiniZincSolver

   result = MiniZincSolver(solver="gecode").solve(model)
   assert result.is_satisfied
   assert result.values["x"] == 2

This foundation intentionally does not yet claim cipher lowering. M10.6b will
lower supported typed components and reproduce a legacy cipher/key-recovery
fixture. Later checkpoints consume shared propagation semantics for trails.

.. automodule:: claasp_next.representations.constraints.cp
   :members:

.. automodule:: claasp_next.drivers.solvers.minizinc
   :members:
