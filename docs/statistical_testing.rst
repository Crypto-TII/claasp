Datasets and statistical testing
================================

Dataset generation is available without NumPy, NIST STS, or Dieharder. A
local seeded random generator makes experiments reproducible without changing
Python's global random state. Inputs and outputs use the same packed MSB-first
convention as normal primitive evaluation.

.. doctest::

   >>> from claasp.analysis import generate_random_dataset
   >>> from claasp.primitives import Speck
   >>> primitive = Speck(number_of_rounds=1)
   >>> data = generate_random_dataset(primitive, 3, seed=17, fixed_inputs={"key": 0})
   >>> data.seed, len(data.samples), [sample.input("key") for sample in data.samples]
   (17, 3, [0, 0, 0])

Avalanche analysis evaluates each sampled baseline and every one-bit
perturbation of the selected input. Matrix rows and columns are input and
output bits in MSB-first order:

.. doctest::

   >>> result = primitive.analysis.avalanche(
   ...     "plaintext", 4, seed=9, fixed_inputs={"key": 0}
   ... )
   >>> result.input_bit_count, result.output_bit_count
   (32, 32)
   >>> result.probabilities[0]
   (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
   >>> result.complete, result.method
   (False, 'empirical_paired_evaluation')

The probability matrix is empirical evidence, never a proof of the strict
avalanche criterion. NIST STS and Dieharder are available through optional
drivers and parsers.

Streaming dataset families
--------------------------

The correlation, CBC, low-density, and high-density families are lazy and
re-iterable. They expose immutable records or fixed-width big-endian byte
blocks without materializing the complete experiment:

.. doctest::

   >>> from claasp.analysis import cbc_dataset, low_density_dataset
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

Correlation uses the output-XOR-input construction. CBC begins at the zero
chaining value and feeds each output into the next evaluation.
Density datasets contain weight zero and one inputs plus a seeded ratio of
weight-two inputs; high density uses their bitwise complements. Seeded
selection makes the chosen subset reproducible. Round-specific streams are
not currently part of the public API.

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

External-suite result artifacts
-------------------------------

NIST STS and Dieharder remain optional external programs. Their text artifacts
can be parsed in a minimal CLAASP installation, without NumPy, SciPy, or the
executables themselves:

.. doctest::

   >>> from claasp.drivers.statistical import parse_dieharder_report
   >>> report = parse_dieharder_report(
   ...     "diehard_birthdays|0|100|100|0.50000000|PASSED\n"
   ... )
   >>> report.passed_count, report.weak_count, report.failed_count
   (1, 0, 0)
   >>> report.observations[0].test_name
   'diehard_birthdays'

The NIST summary parser retains all ten uniformity bins, duplicate subtests,
undefined ``----`` p-values, unavailable ``------`` proportions, and starred
failures. The baseline regression parses all 188 rows in each of the five
committed reference-suite reports. Empty or malformed reports raise an error
instead of fabricating a failed scientific observation.

The optional Dieharder adapter streams a dataset to an isolated temporary
file and invokes the external program without a shell. It records the exact
dataset hash, stable command arguments, tool version, runtime, and captured
diagnostics in a ``StatisticalTestRun``. For
example, ``DieharderDriver(timeout_seconds=10).run(stream, test=0)`` runs one
bounded test when ``dieharder`` is installed. A dedicated CI job exercises
the real executable; importing and parsing results never requires it.

The optional NIST STS adapter has a different execution contract than
Dieharder's: the patched, non-interactive ``assess`` build this project
compiles from ``required_dependencies/`` (applied on top of the official
``sts-2_1_2.zip`` release, mirroring ``docker/Dockerfile``) never prints its
report to stdout. It ``chdir``s into a compile-time constant working
directory and always (re)writes the very same fixed report file,
``<working_dir>/experiments/AlgorithmTesting/finalAnalysisReport.txt``, for
every run. ``NistStsDriver`` locates and reads that fixed path immediately
after each run instead of trusting stdout, serializes invocations against
the same working directory with an in-process lock plus a best-effort
cross-process file lock, and refuses to parse a report whose modification
time did not advance -- guarding against silently returning a stale report
from a previous run. It also does not treat ``assess``'s own exit code as a
success signal, since the tool's convention is inverted (a fully successful
run returns ``1``; a bad-usage invocation returns ``0``). For example,
``NistStsDriver(timeout_seconds=10).run(stream, number_of_bit_streams=1)``
runs one bounded pass over every NIST STS test when ``niststs`` is
installed. A dedicated CI job builds the patched tool from source and
exercises it; importing and parsing results never requires it.
