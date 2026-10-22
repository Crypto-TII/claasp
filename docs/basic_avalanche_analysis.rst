Avalanche tests
===============

How quickly does a one-bit plaintext change spread through Speck?
Create the primitive and run the analysis with its defaults:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=7)
   result = primitive.analysis.avalanche()

Print the avalanche probability-vector statistics for each round:

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
   Path("_build/avalanche_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/avalanche_basic_terminal.txt
   :language: text

Plot the minimum, maximum and average of those same probability vectors:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

The analysis uses NumPy and 1,000 samples by default. Each plaintext bit is
flipped independently, with random plaintexts and keys. The default report
and plot summarize the probability vectors across input/output-bit pairs;
probability 0.5 is the ideal target. The SAC check accounts for sample count
and all measured bit pairs, using 95% simultaneous confidence. “Consistent”
means no deviation was detected at this resolution, rather than proof of SAC.
The plot shows the same sample-dependent band.

Download :download:`the script <examples/basic_avalanche.py>`.
For metrics, criterion checks, parameter choices, and other views, continue to
:doc:`advanced_avalanche_analysis`.
