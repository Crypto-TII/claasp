Linear trail search: advanced
=============================

Linear search uses the same graph facade and retains each LAT correlation
sign. For three-round PRESENT, the minimum trail weight is 4:

.. doctest::

   >>> from claasp.primitives import Present
   >>> result = Present(number_of_rounds=3).analysis.find_optimal_trail(
   ...     kind="xor_linear", backend="dependency_free"
   ... )
   >>> (result.trail.total_weight, result.is_optimal)
   (4.0, True)
   >>> any(step.transition.sign == -1 for step in result.trail.steps)
   True

ARX linear masks use an exact signed carry automaton as well. The same facade
call finds a minimum-weight characteristic for four-round Speck32/64:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> result = Speck(number_of_rounds=4).analysis.find_optimal_trail(
   ...     kind="xor_linear", backend="dependency_free"
   ... )
   >>> (result.trail.total_weight, result.is_optimal)
   (3.0, True)
   >>> (hex(result.trail.input_pattern.value), hex(result.trail.output_pattern.value))
   ('0x40b010c1', '0x2c102010')

Word-graph characteristics can also be enumerated with
``primitive.analysis.enumerate_xor_linear_trails(maximum_weight, solver=solver)``.
The default fixes the key value to zero and folds its dependent subgraph;
``nonzero_input="key"`` includes key-schedule masks instead. Results retain graph/realization identities, solver
version, signed component correlations, and proof-completeness metadata.
``require_complete()`` rejects a caller-limited enumeration. Characteristics
are not a sum over trails or a whole-primitive linear-hull claim.
