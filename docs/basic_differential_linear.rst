Differential-linear analysis: introduction
==========================================

Search a short primitive using a differential prefix, a deterministic-truncated
middle and a linear suffix:

.. code-block:: python

   from claasp.primitives import Speck

   result = Speck(number_of_rounds=3).analysis.find_optimal_differential_linear_trail()
   result.to_terminal()

The optional Kissat solver explores valid nonempty partitions. The reported
score is a characteristic-model objective: the differential component
probability times the square of the linear component correlation. It is not a
measurement of the whole primitive's differential-linear correlation.
