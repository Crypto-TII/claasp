Inspecting and displaying results
=================================

Analysis results expose projected logical values, status, runtime, backend,
model statistics, reproducibility metadata, and the raw backend result.

Cipher diagrams
---------------

.. warning::

   Routed ASCII-art cipher diagrams are a **work in progress**. The current
   ASCII output is a temporary structural listing of rounds, components, and
   logical-unit dependencies. Calling ``cipher.draw("ascii")`` emits
   ``ASCIIArtWorkInProgressWarning`` so applications do not mistake this
   listing for the intended diagram renderer.

The temporary output remains available without an optional dependency:

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
   >>> print(cipher.draw("ascii", trace))
   cipher aes
   inputs
     plaintext  # 16 units
     key  # 16 units
   round 0
     initial_add_round_key: Add <- plaintext[0:16], key[0:16]  # 16 units
   round 1
     key_sub_word_1: S Box <- key[13,14,15,12]  # (0x63,0x63,0x63,0x63)
     key_round_constant_1: Constant <-   # (0x1,0x0,0x0,0x0)
     key_add_constant_1: Add <- key_sub_word_1[0:4], key_round_constant_1[0:4]  # (0x62,0x63,0x63,0x63)
     key_word_4: Add <- key[0:4], key_add_constant_1[0:4]  # (0x62,0x63,0x63,0x63)
     key_word_5: Add <- key[4:8], key_word_4[0:4]  # (0x62,0x63,0x63,0x63)
     key_word_6: Add <- key[8:12], key_word_5[0:4]  # (0x62,0x63,0x63,0x63)
     key_word_7: Add <- key[12:16], key_word_6[0:4]  # (0x62,0x63,0x63,0x63)
     round_key_1: Concatenate <- key_word_4[0:4], key_word_5[0:4], key_word_6[0:4], key_word_7[0:4]  # 16 units
     sub_bytes_1: S Box <- initial_add_round_key[0:16]  # 16 units
     shift_rows_1: Permutation <- sub_bytes_1[0:16]  # 16 units
     mix_columns_1: Linear Map <- shift_rows_1[0:16]  # 16 units
     add_round_key_1: Add <- mix_columns_1[0:16], round_key_1[0:16]  # 16 units
   output <- add_round_key_1[0:16]  # 16 units
   <BLANKLINE>

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
