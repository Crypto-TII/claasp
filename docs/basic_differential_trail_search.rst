Differential trail search: introduction
=======================================

An XOR-differential trail describes how differences between two inputs
propagate through the rounds of a cryptographic primitive.

This example searches for a minimum-weight XOR-differential trail in
six-round Speck, using the default search settings.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=6)
   result = primitive.analysis.find_lowest_weight_xor_differential_trail()

Display the trail and its round-by-round probabilities:

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
   Path("_build/differential_trail_basic_terminal.txt").write_text(
       output.getvalue(), encoding="utf-8"
   )

.. literalinclude:: _build/differential_trail_basic_terminal.txt
   :language: text

The report shows the XOR difference at the end of each round, the
relative probability of each round transition, and the cumulative
probability of the trail.

For six-round Speck, the search finds a trail with total weight 13,
corresponding to a probability of :math:`2^{-13}` (1/8192). The message
"Proved optimal" indicates that no lower-weight trail exists under
the search model and its constraints.

Download :download:`the executable script <examples/basic_differential_trail_search.py>`.

For additional search parameters and detailed results, see
:doc:`advanced_differential_trail_search`.
