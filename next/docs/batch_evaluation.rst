Batch evaluation
================

``BatchEvaluator`` invokes the scalar reference once per batch item.
``TransposedBatchEvaluator`` traverses the graph once and evaluates every lane
at each component. Both return the same result type and retain arbitrary-size
Python integers.

.. doctest::

   >>> from claasp_next.representations.execution import BatchEvaluator, TransposedBatchEvaluator
   >>> from claasp_next.parameters import poseidon_bn254_width3
   >>> primitive = poseidon_bn254_width3().permutation()
   >>> inputs = {"state": ((0, 1, 2), (3, 4, 5))}
   >>> reference = BatchEvaluator().evaluate(primitive, inputs)
   >>> TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == reference.outputs
   True

The transposed backend has no optional dependency. It does not use fixed-width
NumPy integers, which cannot directly hold common proof-system fields.
Benchmark the intended workload with:

.. code-block:: console

   PYTHONPATH=src python tools/benchmark_batch.py --batch-size 32

The benchmark verifies equality before reporting timings. Timings are not CI
assertions because shared runners are noisy.
