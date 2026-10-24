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

**TODO**
