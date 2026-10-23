Component analysis tests
========================

Which operations occur in a primitive, and what are their cryptographic
properties? Discover and analyze the components of two-round PRESENT:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Present

   primitive = Present(number_of_rounds=2)
   result = primitive.analysis.component_analysis()

Print the inventory and default properties:

.. code-block:: python

   result.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   result.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/component_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/component_basic_terminal.txt
   :language: text

Rows describe distinct semantic groups, not just operation names. ``Component``
and the zero-based ``Selector index`` identify the arguments to
``primitive.analysis.component("permutation", index=1)``, for example.
The separate ``Group`` number labels rows in the full inventory. Parameters
show their widths and a short lookup-table or permutation preview. The two
permutations act on the 64-bit state and the 80-bit key; the constants are
five-bit encodings of round values one and two. ``Occurrences`` counts uses of
each exact operation. Use ``result.to_terminal(details=True)`` for the full
indexed tables and provenance.

The same four-bit S-box occurs 34 times, including its uses in the key schedule.
CLAASP groups equivalent operations and computes their properties once. The
S-box has differential uniformity four, nonlinearity four and algebraic degree
three. A bit permutation is invertible but has branch number two: moving bits
alone does not increase the number of active bits.

These are exact local properties, rather than sampled measurements or a
security assessment of the whole primitive. Operations without a default analyzer
remain visible in the inventory. Their absence from the property tables does
not mean they passed a test.

Download :download:`the script <examples/basic_component_analysis.py>`.
Continue to :doc:`advanced_component_analysis` for selecting DES's non-bijective
S-boxes, differential tables,
composite blocks, linear diffusion, and bounded searches.
