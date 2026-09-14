Datasets and statistical testing
================================

Dataset generation is available without NumPy, NIST STS, or Dieharder. A
local seeded random generator makes experiments reproducible without changing
Python's global random state. Inputs and outputs use the same packed MSB-first
convention as normal primitive evaluation.

.. doctest::

   >>> from claasp_next.analysis import generate_random_dataset
   >>> from claasp_next.ciphers import SpeckBlockCipher
   >>> primitive = SpeckBlockCipher(number_of_rounds=1)
   >>> data = generate_random_dataset(primitive, 3, seed=17, fixed_inputs={"key": 0})
   >>> data.seed, len(data.samples), [sample.input("key") for sample in data.samples]
   (17, 3, [0, 0, 0])

Avalanche analysis evaluates each sampled baseline and every one-bit
perturbation of the selected input. Matrix rows and columns are input and
output bits in MSB-first order:

.. doctest::

   >>> result = primitive.analyze().avalanche(
   ...     "plaintext", 4, seed=9, fixed_inputs={"key": 0}
   ... )
   >>> result.input_bit_count, result.output_bit_count
   (32, 32)
   >>> result.probabilities[0]
   (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
   >>> result.complete, result.method
   (False, 'empirical_paired_evaluation')

The probability matrix is empirical evidence, never a proof of the strict
avalanche criterion. Later M10.12 checkpoints add streaming serialization,
dataset hashes, the remaining legacy dataset families, and optional NIST STS
and Dieharder drivers and parsers.
