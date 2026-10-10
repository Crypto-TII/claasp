Quick analysis scripts
======================

These small, copyable examples answer common questions about a primitive and
use only CLAASP's Python implementation. The linked guides explain the full
result types and optional solver backends.

Find an optimal XOR differential trail
---------------------------------------

An XOR differential trail records how an input difference propagates through
the rounds. Its weight is :math:`-\log_2(p)`, where :math:`p` is the trail
probability represented by the model.

.. doctest::

   >>> from claasp.primitives import Speck
   >>> speck = Speck(number_of_rounds=2)
   >>> differential = speck.analysis.find_optimal_trail(
   ...     kind="xor_differential", backend="dependency_free"
   ... )
   >>> differential.show()  # doctest: +ELLIPSIS
   Trail
   ...

The report shows one difference per round, each round's probability, and the
cumulative probability. Its total weight is 1 and the matching lower bound is
1, so this is a proved optimum rather than merely the best trail encountered
so far. Use ``differential.show(details=True)`` to inspect every component and
the search metadata. Another exact backend may choose a different trail with
the same optimal weight. See :doc:`analysis` for constraints, enumeration,
and solver-backed searches.

Find an optimal XOR linear trail
---------------------------------

A linear trail follows masks rather than differences. The interface is the
same:

.. doctest::

   >>> speck = Speck(number_of_rounds=4)
   >>> linear = speck.analysis.find_optimal_trail(kind="xor_linear")
   >>> linear.show()  # doctest: +ELLIPSIS
   Trail
   ...

This report shows input mask ``0x40b010c1``, output mask ``0x2c102010``, and
weight 3. For a linear trail, weight is the negative base-two logarithm of the
absolute trail correlation.

Measure avalanche behavior
--------------------------

The avalanche analysis evaluates random plaintexts, flips each plaintext bit,
and records the observed output-bit changes:

.. doctest::

   >>> speck = Speck(number_of_rounds=2)
   >>> avalanche = speck.analysis.avalanche(
   ...     "plaintext", 8, seed=9, fixed_inputs={"key": 0}
   ... )
   >>> avalanche.sample_count
   8
   >>> round(sum(avalanche.mean_changed_output_bits) / avalanche.input_bit_count, 2)
   9.47

Increase the sample count for an actual experiment. The fixed seed makes runs
with the same parameters reproducible. See :doc:`statistical_testing` for the
probability matrix, dataset families, NIST STS, and Dieharder integration.

Create a neural-distinguisher dataset
-------------------------------------

CLAASP can generate labelled related-pair data without importing a
machine-learning framework:

.. doctest::

   >>> from claasp.analysis import xor_differential_dataset
   >>> dataset = xor_differential_dataset(
   ...     speck,
   ...     {"plaintext": 0x00400000, "key": 0},
   ...     samples=4,
   ...     seed=7,
   ... )
   >>> dataset.sample_count, dataset.feature_width, dataset.labels
   (4, 64, (0, 1, 1, 0))

See :doc:`neural_distinguishers` for dataset partitions and the optional
training driver.

Inspect AES round values
------------------------

When debugging or comparing an implementation with a specification, retain
the intermediate values from one evaluation:

.. doctest::

   >>> from claasp.primitives import AES
   >>> aes = AES(number_of_rounds=2)
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> execution = aes.evaluate_with_trace(plaintext=plaintext, key=key)
   >>> for round_number, outputs in enumerate(aes.graph.intermediate_outputs, start=1):
   ...     value = execution.value_of(outputs["add_round_key"].owner_id)
   ...     print(round_number, bytes(value).hex())
   1 89d810e8855ace682d1843d8cb128fe4
   2 4915598f55e5d7a0daca94fa1f0a63f7

An execution trace is the record of concrete values produced by one run. It
is useful for inspecting intermediate states and is unrelated to the
number-theoretic meaning of "trace". See :doc:`concepts` for the distinction
between an evaluation result and its trace.
