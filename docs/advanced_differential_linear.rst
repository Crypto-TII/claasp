Differential-linear analysis: advanced
======================================

Exploring partitions
--------------------

The automatic workflow searches all nonempty prefix/middle/suffix partitions.
For a focused comparison, fix part or all of the partition:

.. code-block:: python

   from claasp.primitives import Speck
   from claasp.drivers.solvers import KissatSolver

   primitive = Speck(number_of_rounds=4)
   result = primitive.analysis.find_optimal_differential_linear_trail(
       prefix_rounds=1, middle_rounds=1,
       solver=KissatSolver(timeout_seconds=30),
   )
   result.require_complete()
   result.to_terminal()

``input_difference`` and ``output_mask`` optionally fix external boundaries.
Otherwise the model chooses a nonzero input difference and output mask.
``attempted_partitions`` records which partitions were explored; ``partition``
is the best one found. ``found=False`` with ``complete=True`` means no witness
in the declared search model, not the absence of every possible distinguisher.
A solver time limit can raise the driver's timeout exception. Unknown results
remain incomplete and cannot pass ``require_complete()``.

Interpreting the objective
--------------------------

The exact score is ``P_D * C_L**2``, using rational transition counts; the
corresponding displayed weight is ``w_D + 2*w_L``. Integer numerator circuits
optimize this score without rounding fractional S-box weights. Each witness
is checked against its component relations and both middle connectors.
Optimality is relative to these characteristic and connector constraints.

The deterministic middle contributes support constraints and no estimated
probability. A high model score, particularly for very few rounds, does not
establish a useful attack or a whole-primitive correlation. Confirm candidate
pairs with an independent empirical experiment or the applicable theoretical
argument. The lower-level semi-deterministic and paired-input models remain
separate models with their own evidence and objective conventions; this
workflow does not relabel those conventions as the exact score above.

The slices must expose round-state boundaries and have supported propagation
relations. Unsupported components or inverse requirements fail explicitly.
