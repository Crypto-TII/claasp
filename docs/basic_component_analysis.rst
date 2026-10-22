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

The same four-bit S-box occurs 34 times, including its uses in the key schedule.
CLAASP groups equivalent operations and computes their properties once. The
S-box has differential uniformity four, nonlinearity four and algebraic degree
three. A bit permutation is invertible but has branch number two: moving bits
alone does not increase the number of active bits.

These are exact local properties, rather than sampled measurements or a
security assessment of the whole cipher. Operations without a default analyzer
remain visible in the inventory. Their absence from the property tables does
not mean they passed a test.

Download :download:`the script <examples/basic_component_analysis.py>`.
Continue to :doc:`advanced_component_analysis` for S-box differential tables,
composite blocks, linear diffusion, and bounded searches.
