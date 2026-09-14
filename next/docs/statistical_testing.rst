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
avalanche criterion. Later M10.12 checkpoints add the remaining optional NIST
STS and Dieharder drivers and parsers.

Streaming dataset families
--------------------------

The correlation, CBC, low-density, and high-density families are lazy and
re-iterable. They expose immutable records or fixed-width big-endian byte
blocks without materializing the complete experiment:

.. doctest::

   >>> from claasp_next.analysis import cbc_dataset, low_density_dataset
   >>> cbc = cbc_dataset(
   ...     primitive, "plaintext", 1, 3, seed=7, fixed_inputs={"key": 0}
   ... )
   >>> [record.value for record in cbc]
   [0, 0, 0]
   >>> list(cbc.iter_bytes())
   [b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00']
   >>> density = low_density_dataset(
   ...     primitive, "plaintext", 1, ratio=0, fixed_inputs={"key": 0}
   ... )
   >>> density.block_count, tuple(density.iter_selected_inputs())[:3]
   (33, (0, 2147483648, 1073741824))

Correlation retains the legacy output-XOR-input construction. CBC begins at
the zero chaining value and feeds each output into the next evaluation.
Density datasets contain weight zero and one inputs plus a seeded ratio of
weight-two inputs; high density uses their bitwise complements. The v5 seeded
selection removes the legacy generator's nondeterministic subset behavior.
Round-specific streams await the stable public trace-projection API.

Serialization and identity
--------------------------

Statistical streams serialize as raw fixed-width output records in
sample-major, then block-major order. Logical bits are MSB-first and bytes are
big-endian. The manifest binds those conventions to construction parameters,
the primitive realization, and the SHA-256 digest of the exact byte stream:

.. doctest::

   >>> stream = cbc_dataset(
   ...     primitive, "plaintext", 1, 3, seed=7, fixed_inputs={"key": 0}
   ... )
   >>> manifest = stream.manifest()
   >>> manifest.record_count, manifest.byte_count
   (3, 12)
   >>> manifest.sha256
   '15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b'
   >>> manifest.bit_order, manifest.byte_order, manifest.record_order
   ('msb_first', 'big', 'sample_major_then_block')

``write_binary(file)`` writes incrementally and returns the byte count;
``manifest.to_json()`` provides canonical compact JSON suitable for storing
beside that file. Computing a digest re-evaluates the lazy dataset and never
changes global random state.
