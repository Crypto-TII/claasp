Continuous diffusion tests
==========================

How does a small continuous change in an input spread through AES?
Measure the continuous avalanche factor (CAF) with the default settings:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import AES

   primitive = AES()
   result = primitive.analysis.continuous_diffusion()

Print the round-by-round result:

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
   Path("_build/continuous_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/continuous_basic_terminal.txt
   :language: text

Display those same measurements:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

The default experiment uses 16 input pairs, a perturbation bound of 0.001,
and 80 decimal digits of evaluation precision. Sampling uses a seeded NumPy
generator. One randomly selected plaintext
coordinate moves slightly inward from a Boolean endpoint; the key is shared
within each pair. CAF measures the resulting changes of output signs.
A value near one is the random-sign reference, rather than a security criterion.

Download :download:`the script <examples/basic_continuous_diffusion.py>`.
Continue to :doc:`advanced_continuous_diffusion` for the sampling convention,
ToyAES, perturbation choices, precision, and heatmap/3D views of per-output
CAF contributions.
