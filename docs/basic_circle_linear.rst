Circle-linear trails: basic
===========================

Find a strong trail through eight rounds of CRAFT using circle-linear bit
checks. A **mask** identifies a **check**, a function that returns one bit
from a state value. A trail records these checks across successive rounds.
This example keeps the alternative addition fixed; the search runs directly
in Python.

.. include:: _includes/craft_circle_operation.txt

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Craft
   from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace

   operation = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
   primitive = Craft(number_of_rounds=8)
   result = primitive.analysis.find_lowest_weight_circle_linear_trail(
       bibrace=operation, fixed_inputs={"tweak": 0}
   )

The ``bibrace`` argument selects the displayed operation. CRAFT also takes a
**tweak**, an additional nonsecret input that selects an encryption variant
without changing the secret key. Here ``fixed_inputs={"tweak": 0}`` sets it to
zero. The secret key is left unspecified; the search derives conditions on
the keys for which the trail contributes. The advanced guide shows how to
select other operations and inspect the underlying model.

Print the round masks, absolute correlations and cumulative absolute trail
contributions:

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

The **correlation** between two checks is the fraction of inputs on which
they agree minus the fraction on which they disagree.

``Relative |correlation|`` is :math:`|c_i|`, the absolute correlation of
round transition :math:`i`. ``Cumulative |trail contribution|`` is
:math:`|\prod_{j=1}^{i} c_j|`, the absolute product along the selected trail.
These absolute values apply on the reported **key class**: the set of keys
satisfying the conditions found by the search. Signs can depend on the key.
The cumulative column gives the selected trail's contribution; the full
input/output correlation sums contributions from all trails with the same
input and output checks. Use ``result.to_terminal(details=True)`` to also
inspect the search settings, conditions on the key and weight of each round.

Plot the weight contributed by each round and its running total:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

The horizontal axis numbers rounds within this segment, starting with input
at zero. Each additional bit of weight halves the absolute trail
contribution. The relative line shows each round's weight; the cumulative
line adds them.

The model searches a restricted set of checks called a **subgroup**: XORing
any two checks in the set gives another check in the set. These checks have
**perfect** relations through the S-box (the substitution lookup table): the
checks before and after it always agree or always disagree. Optimality applies
to this restricted set. Other trails may reinforce or cancel the selected
trail's contribution to the full input/output correlation.

Plotting requires the optional ``presentation`` dependencies described in
:doc:`getting_started`. Use ``result.plot(show=False)``
to return a figure without displaying it, or
``result.plot(save_to="circle-trail.png")`` to save it. Reporting reuses the
result and does not repeat the search.

Download :download:`the script <examples/basic_circle_linear.py>`.
For direct input/output correlations see :doc:`basic_circle_linear_correlations`.
For definitions, configuration and numerical CRAFT checks, continue to
:doc:`advanced_circle_linear`.
