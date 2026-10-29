Statistical tests: advanced
===========================

This guide covers statistical-test datasets and result artifacts independently
of how the input data was generated. It does not construct or analyze a
primitive.

Reading external-suite reports
------------------------------

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


Running tests on supplied datasets
----------------------------------

``SuppliedStatisticalDataset`` accepts a flat bit iterable, including a NumPy
array, without depending on the source of the data. Use the existing optional
NIST STS executable for the full suite:

.. code-block:: python

   import numpy as np
   from claasp.analysis import SuppliedStatisticalDataset
   from claasp.drivers.statistical import NistStsDriver

   bits = np.random.default_rng(9).integers(0, 2, 100_000, dtype=np.uint8)
   dataset = SuppliedStatisticalDataset.from_bits(bits)
   run = NistStsDriver().run(
       dataset, number_of_bit_streams=10, bits_per_sequence=10_000,
       test_selection="111110000000001",
   )

The mask selects frequency, block frequency, cumulative sums, runs, longest
run and linear complexity, in the standard NIST order. The default selects all
15 tests. Choose sequence sizes appropriate to the selected tests; 10,000 bits
is an interface example, not a sufficient size for every test. NIST recommends
at least 1,000,000 bits for several tests. Undefined values and unavailable
proportions remain explicit in the parsed report. With few sequences,
uniformity estimates are unreliable.

Use files with an explicit encoding:

.. code-block:: python

   dataset = SuppliedStatisticalDataset.from_file("data.bin")  # packed bytes
   # Or: from_file("data.txt", input_format="ascii") for zeros/ones and whitespace.
   run = NistStsDriver().run(dataset, number_of_bit_streams=10)

Packed bits use most-significant-bit order. The driver requires exact sequence
sizes and does not silently discard leftover bits. Non-32-bit-aligned sequence
boundaries use the executable's ASCII reader to avoid the packed reader's
chunk truncation. The result retains the packed-byte SHA-256, stable command,
execution time and report. ``dataset.bit_count`` identifies meaningful bits in
the final packed byte; remaining padding bits are zero.

Interpreting the result
-----------------------

``run.report.rows`` retains each subtest's ten p-value bins, uniformity p-value,
and passed/total sequence counts. A p-value below the test's significance level
is evidence against its null hypothesis; passing a selection of tests does not
establish unpredictability. Use independent sequences and enough observations
for both per-sequence tests and the aggregate assessment.

The native ``frequency_test`` uses section 2.1 of
`NIST SP 800-22 Rev. 1a <https://doi.org/10.6028/NIST.SP.800-22r1a>`_ and has an
explicit ``alpha`` parameter. The external suite uses its compiled
significance level (normally 0.01); the native parameter does not configure it.
