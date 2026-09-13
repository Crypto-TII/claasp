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

Cipher solving and key recovery
-------------------------------

The CP representation can lower the portable Boolean formula already produced
from supported typed cipher components. MiniZinc-safe encoded identifiers are
kept internal and results are mapped back to stable graph names. Consequently
the ordinary analysis API works unchanged:

.. code-block:: python

   from claasp_next.ciphers import SpeckBlockCipher
   from claasp_next.drivers.solvers import MiniZincSolver

   cipher = SpeckBlockCipher(number_of_rounds=1)
   plaintext = 0x6574694C
   ciphertext = cipher.evaluate(plaintext, 0x1918111009080100)
   result = cipher.analyze().recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
       solver=MiniZincSolver(),
   )
   assert cipher.evaluate(plaintext, result.value("key")) == ciphertext

A dedicated external test also reproduces the legacy full 22-round
Speck32/64 fixed-input result ``0xa86842f2``. Both recovery and the legacy
fixture are checked with scalar evaluation rather than trusting solver status.
Later checkpoints consume shared propagation semantics for trails.

.. automodule:: claasp_next.representations.constraints.cp
   :members:

.. automodule:: claasp_next.drivers.solvers.minizinc
   :members:
