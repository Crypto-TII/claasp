Batch evaluation
================

A *batch* is a collection of independent primitive inputs evaluated together.
For a block cipher, each batch item contains one plaintext and one key. Batch
evaluation is useful for test vectors, experiments, and datasets; it does not
connect one item's output to the next item.

Two evaluators implement the same public contract:

* ``BatchEvaluator`` evaluates the complete graph once for item 0, then once
  for item 1, and so on. It is the straightforward reference implementation.
* ``TransposedBatchEvaluator`` visits the graph once. At each component it
  evaluates that component for all items, called *lanes*, before moving to the
  next component.

"Transposed" describes this change in loop order. It does not transpose the
cryptographic state or change input/output ordering. Both evaluators return
one ordinary evaluation result per input item.

AES example
-----------

The low-level batch interface uses tuples of logical units. AES has sixteen
byte-field units in each plaintext and key, so two AES inputs are written as
two 16-element tuples:

.. doctest::

   >>> from claasp.primitives import AES
   >>> from claasp.representations.execution import BatchEvaluator, TransposedBatchEvaluator
   >>> aes = AES()
   >>> key = tuple(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
   >>> inputs = {
   ...     "plaintext": (
   ...         tuple(bytes.fromhex("00112233445566778899aabbccddeeff")),
   ...         (0,) * 16,
   ...     ),
   ...     "key": (key, key),
   ... }
   >>> reference = BatchEvaluator().evaluate(aes, inputs)
   >>> [bytes(output).hex() for output in reference.outputs]
   ['69c4e0d86a7b0430d8cdb78070b4c55a', 'c6a13b37878f5b826f4f8162a1c8d879']
   >>> transposed = TransposedBatchEvaluator().evaluate(aes, inputs)
   >>> transposed.outputs == reference.outputs
   True

The transposed evaluator uses ordinary Python tuples and integers. It has no
NumPy dependency and does not truncate large field elements to a machine-word
width.

Choosing an evaluator
---------------------

Use ``BatchEvaluator`` as the clearest correctness reference. Use
``TransposedBatchEvaluator`` when one graph traversal is a better fit for the
batch size and component mix. Measure the workload you actually use; the
transposed order is not guaranteed to be faster for every primitive or batch
size.

From the repository root, the bundled benchmark first checks that both
evaluators agree and then reports timings:

.. code-block:: console

   PYTHONPATH=src python tools/benchmark_batch.py --batch-size 32

Timings are not CI assertions because shared runners are noisy.
