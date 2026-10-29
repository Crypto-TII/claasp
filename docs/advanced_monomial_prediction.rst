Monomial prediction and division property: advanced
===================================================

Reusing exact ANFs
------------------

Select one output bit, all outputs, or an intermediate component by id:

.. code-block:: python

   from claasp.primitives import Simon

   primitive = Simon(number_of_rounds=2)
   result = primitive.analysis.anf(output_bit=0)
   result.to_terminal(details=True)
   all_outputs = primitive.analysis.anf()

``component="..."`` selects that component's bits. Concrete ``fixed_inputs``
are substituted before expansion. ``maximum_terms`` (default 100,000) bounds
the terms retained in any intermediate polynomial; ``maximum_operations``
(default 1,000,000) bounds monomial products. A limit raises an error and never
returns a partial ANF. Other input names use their full name plus an underscore
to avoid collisions between similarly named inputs.

Use ``result.degree_in(("p1", "p8"))`` to count only selected variables,
keeping other variables symbolic. ``result.coefficient(("p1", "p8"))``
returns the coefficient of that exact monomial. ``result.superpoly(("p1",))``
extracts the symbolic cube coefficient; optional ``fixed_variables`` substitute
variables outside the cube. These operations reuse the retained polynomials.

Division-property degree bounds
-------------------------------

For larger expansions, use the optional GLPK solver (or pass another portable
MILP solver):

.. code-block:: python

   bound = primitive.analysis.algebraic_degree(output_bit=0)
   print(bound.upper_bound)
   exact = primitive.analysis.algebraic_degree(output_bit=0, exact=True)
   exact.require_complete()
   print(exact.exact_degree)

The default returns a reachable-monomial upper bound, not an exact algebraic
degree. Exact mode enumerates candidate leading-degree paths to UNSAT,
projects complete input monomials and cancels equal terms modulo two. If all
leading terms cancel, it searches lower degrees. A zero polynomial has degree
-1. ``variable_input`` selects the input whose degree is counted; the other
inputs remain symbolic. ``variable_positions`` optionally counts only a
subset of bits without fixing the other bits to zero. The supported operations follow the Boolean monomial
MILP model; unsupported operations raise an explicit error.

``maximum_paths`` (default 10,000) limits the total path enumeration. A limit or
unfinished solver result leaves ``complete=False`` and ``exact_degree=None``.
It does not turn provisional parity into a proof. Set a practical timeout in
the supplied solver as well. Solver timeouts may raise the driver's timeout
exception.

Recovering cube superpolys without a truth table
------------------------------------------------

.. code-block:: python

   superpoly = primitive.analysis.superpoly((1, 8), output_bit=0)
   superpoly.require_complete()
   superpoly.to_terminal()

This keeps variables outside the cube symbolic and recovers the cube coefficient by complete monomial-path parity.
``cube_input`` selects another cube input. Set ``zero_outside_cube=True``
to fix positions outside the cube in that input to zero, obtaining its key
coefficient. The work depends on model paths,
rather than enumerating every assignment of all key and cube bits; worst-case
cost remains exponential. If the path limit is reached, ``polynomial`` is
``None`` and no provisional superpoly is printed.

For a small independent check, ``CubeSuperpolyQuery`` in
``claasp.representations.constraints.milp`` evaluates the complete selected
cube and symbolic subspace, then applies the Möbius transform. Its explicit
dimension guard is appropriate for verification, not large-scale recovery.
The integration tests compare solver-recovered coefficients with exact ANFs
and test cancellation on a function whose two identical XOR terms sum to zero.
