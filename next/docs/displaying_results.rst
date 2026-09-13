Inspecting and displaying results
=================================

Analysis results expose projected logical values, status, runtime, backend,
model statistics, reproducibility metadata, and the raw backend result.

Cipher diagrams
---------------

Every cipher can produce a readable structural diagram without an optional
dependency. The ASCII form shows rounds, components, and the logical units
selected by each dependency.

.. doctest::

   >>> from claasp_next.ciphers import AESBlockCipher
   >>> cipher = AESBlockCipher(number_of_rounds=1)
   >>> drawing = cipher.draw("ascii")
   >>> drawing.startswith("cipher aes\ninputs\n")
   True
   >>> "round 0" in drawing and "output <-" in drawing
   True

Passing an execution trace displays intermediate values on the same graph.
TikZ source is available with ``cipher.draw("tikz", trace)``; PDF output with
``cipher.draw("pdf", trace)`` additionally requires the ``pdflatex`` command.

.. doctest::

   >>> trace = cipher.evaluate_with_trace(0, 0).trace
   >>> "#" in cipher.draw("ascii", trace)
   True

Analysis reports
----------------

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
