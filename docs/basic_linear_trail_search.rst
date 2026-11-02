Linear trail search: introduction
=================================

Did you know that CLAASP can exploit SAT solvers to find and show an optimal 6-round XOR linear trail of SPECK32/64 in seconds?

By default the search uses Kissat, so the ``kissat`` executable must be
installed and on your ``PATH``.

Just do:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=6)
   trail = primitive.analysis.find_lowest_weight_xor_linear_trail()

Print the resulting trail:

.. code-block:: python

   trail.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   trail.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/linear_trail_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/linear_trail_basic_terminal.txt
   :language: text

Use ``trail.to_terminal(details=True)`` to also see how the search was run
and proved optimal, and the mask, correlation and weight of every component.
