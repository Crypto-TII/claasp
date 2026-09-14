Inspecting and displaying results
=================================

Analysis results expose projected logical values, status, runtime, backend,
model statistics, reproducibility metadata, and the raw backend result.

Primitive diagrams
-------------------

Routed ASCII-art primitive diagrams are available without an optional
dependency.  Boxes identify graph nodes and labelled connectors preserve each
input's declared position and logical-unit selection:

.. doctest::

   >>> from claasp_next.primitives import AES
   >>> primitive = AES(number_of_rounds=1)
   >>> drawing = primitive.draw("ascii")
   >>> drawing.startswith("primitive aes\ninputs\n")
   True
   >>> "round 0" in drawing and "output\n" in drawing
   True
   >>> "[0] plaintext[0:16]" in drawing and "--+-->" in drawing
   True

Passing an execution trace displays intermediate values on the same graph.
TikZ source is available with ``primitive.draw("tikz", trace)``; PDF output with
``primitive.draw("pdf", trace)`` additionally requires the ``pdflatex`` command.

.. doctest::

   >>> trace = primitive.evaluate_with_trace(0, 0).trace
   >>> traced_drawing = primitive.draw("ascii", trace)
   >>> "| initial_add_round_key |" in traced_drawing
   True
   >>> "| # (0x63,0x63,0x63,0x63) |" in traced_drawing
   True
   >>> "[0] add_round_key_1[0:16] --> +------------+" in traced_drawing
   True

Analysis reports
----------------

.. doctest::

   >>> from claasp_next import Bit, Primitive, ValueType
   >>> from claasp_next.analysis import AnalysisResult
   >>> [field for field in AnalysisResult.__dataclass_fields__ if field != "solver_result"]
   ['status', 'values', 'runtime_seconds', 'backend', 'statistics', 'reproducibility']

Values use the same packed-integer conventions as primitive evaluation, so they
can be displayed with ordinary formatting such as ``hex(result.value("key"))``.

The legacy CLAASP ``Report`` class has not yet been migrated. A future
reporting milestone will add pleasant terminal, notebook, and HTML views over
the stable result objects. Presentation must remain separate from solver
execution: a report renders a result and its provenance but does not reinterpret
or silently recompute it.
