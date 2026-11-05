Circle-linear trails: introduction
==================================

Find a strong trail through eight rounds of CRAFT using circle-linear bit
checks. This example keeps the alternative addition fixed while searching
for the trail, and needs no solver.

.. include:: _includes/craft_circle_operation.txt

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Craft
   from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace

   operation = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
   primitive = Craft(number_of_rounds=8)
   result = primitive.circle_linear_trail_model(bibrace=operation).search()

The explicit ``bibrace`` argument selects the displayed operation. It is also
the default of CRAFT's convenience method. The advanced guide shows how to
select and compare other operations.

Print the round masks and relative and cumulative contribution magnitudes:

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
   Path("_build/circle_linear_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/circle_linear_basic_terminal.txt
   :language: text

The magnitudes apply on the reported key class; signs can depend on the key.
Use ``result.to_terminal(details=True)`` to also inspect search metadata, key
constraints and the weight of each round.

Plot the weight contributed by each round and its running total:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

The horizontal axis numbers rounds within this segment, starting with input
at zero. Weight is measured in bits: each bit halves the trail's correlation
magnitude. The relative line shows each round's contribution; the cumulative
line adds them. The result is optimal inside the reported subgroup, a set of
compatible checks closed under XOR. Its key class describes where this trail
contributes. Other trails may reinforce or cancel it, so the plot is not a
claim about the full input/output correlation.

Plotting requires the ``presentation`` extra. Use ``result.plot(show=False)``
to return a figure without displaying it, or
``result.plot(save_to="circle-trail.png")`` to save it. Reporting reuses the
result and does not repeat the search.

Download :download:`the script <examples/basic_circle_linear.py>`.
For direct input/output correlations see :doc:`basic_circle_linear_correlations`.
For definitions, configuration and numerical CRAFT checks, continue to
:doc:`advanced_circle_linear`.
