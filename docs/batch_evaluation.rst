Evaluating primitives
=====================

One binary input
----------------

At ordinary cipher boundaries, pass one packed Python integer for each named
input. The returned integer uses the primitive's documented bit width:

.. doctest::

   >>> from claasp.primitives import AES
   >>> aes = AES()
   >>> output = aes.evaluate(
   ...     plaintext=0x00112233445566778899AABBCCDDEEFF,
   ...     key=0x000102030405060708090A0B0C0D0E0F,
   ... )
   >>> f"{output:032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

Several binary inputs
---------------------

``evaluate_many()`` evaluates independent inputs. A list varies an input;
one scalar value is reused for the whole batch. Here two plaintexts share one
key:

.. doctest::

   >>> plaintexts = [0x0, 0x1]
   >>> outputs = aes.evaluate_many(plaintext=plaintexts, key=0x0)
   >>> [f"{value:032x}" for value in outputs]
   ['66e94bd4ef8a2c3b884cfa59ca342b2e', '58e2fccefa7e3061367f1d57a4e7455a']

Supply lists of the same length to pair each plaintext with a different key:

.. doctest::

   >>> keys = [0x0, 0x1]
   >>> outputs = aes.evaluate_many(plaintext=plaintexts, key=keys)
   >>> [f"{value:032x}" for value in outputs]
   ['66e94bd4ef8a2c3b884cfa59ca342b2e', 'a17e9f69e4f25a8b8620b4af78eefd6f']

Non-binary inputs
-----------------

For a vector over a prime field, pass a tuple containing one integer per field
element. The output preserves that logical-unit structure:

.. doctest::

   >>> from claasp import PrimitiveBuilder, PrimeField, ValueType
   >>> from claasp.components import Add
   >>> vector = ValueType(domain=PrimeField(17), shape=(3,))
   >>> builder = PrimitiveBuilder("field_add", {"left": vector, "right": vector})
   >>> builder.add_round()
   Round(number=0)
   >>> result = builder.add_component(Add(builder.inputs()))
   >>> field_add = builder.build(result)
   >>> field_add.evaluate(left=(1, 2, 3), right=(4, 5, 16))
   (5, 7, 2)

The final coordinate is ``3 + 16 = 2`` modulo 17. See :doc:`concepts` for
``ValueType`` and the available mathematical domains.

Lower-level batch evaluation
----------------------------

A *batch* is a collection of independent primitive inputs evaluated together.
For a block cipher, each batch item contains one plaintext and one key. Batch
evaluation is useful for test vectors, experiments, and datasets; it does not
connect one item's output to the next item.

For routine packed-integer inputs, prefer ``primitive.evaluate_many()``. The
rest of this page describes the lower-level execution representation used when
callers already have logical-unit tuples or want to choose a batch traversal
strategy.

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
