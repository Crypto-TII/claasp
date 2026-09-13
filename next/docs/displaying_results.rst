Inspecting and displaying results
=================================

Analysis results expose projected logical values, status, runtime, backend,
model statistics, reproducibility metadata, and the raw backend result.

.. doctest::

   >>> from claasp_next import Bit, Cipher, ValueType
   >>> from claasp_next.analysis import AnalysisResult
   >>> [field for field in AnalysisResult.__dataclass_fields__ if field != "solver_result"]
   ['status', 'values', 'runtime_seconds', 'backend', 'statistics', 'reproducibility']

Values use the same packed-integer conventions as cipher evaluation, so they
can be displayed with ordinary formatting such as ``hex(result.value("key"))``.

The legacy CLAASP ``Report`` class has not yet been migrated. A future
reporting milestone will add pleasant terminal, notebook, and HTML views over
the stable result objects. Presentation must remain separate from solver
execution: a report renders a result and its provenance but does not reinterpret
or silently recompute it.
