Neural differential distinguishers: inputs and intermediate states
==================================================================

Start with :doc:`basic_neural_differential`. Positive examples encrypt related
input pairs with the requested XOR difference; negative examples encrypt
independent random input pairs. Features concatenate the two outputs, rather
than their XOR. With the default zero key difference, positive examples share
a key within each pair, but keys vary across pairs; negative keys are sampled
independently. Specify ``fixed_inputs={"key": 0}`` to hold the key fixed in
both classes. This changes the experiment, so report the setting.

A fixed-key experiment and an intermediate component
----------------------------------------------------

The first experiment below uses the final output. The second projects only the
right word of round one, read from the execution trace. It illustrates how
feature selection changes the question being learned:

.. literalinclude:: examples/advanced_neural_differential.py
   :language: python
   :start-at: from claasp
   :end-before: if __name__

.. plot::
   :context: reset
   :nofigs:
   :include-source: false

   import runpy

   run_example = runpy.run_path("examples/advanced_neural_differential.py")["run_example"]
   result, projected_result = run_example()

.. code-block:: python

   result, projected_result = run_example()
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
   Path("_build/advanced_neural_differential.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_neural_differential.txt
   :language: text

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

Report or plot the intermediate-state training history independently:

.. plot::
   :context: close-figs
   :include-source:

   projected_result.plot()

``component_output_dataset`` provides the analogous black-box projection.
``round_component_ids`` selects every component built in a round, including
intermediates and key operations; it is not a selector for just the final
round state. A single ``source_id`` selects the exact wire shown above.

To study related keys, pass ``input_differences={"plaintext": 0x400000,
"key": 1}`` to ``primitive.analysis.neural_differential`` and omit the fixed
key. Unspecified differences are zero. A fixed input must have zero difference.
Use separate runs for each round count and difference, with a test partition
reserved before selection as in :doc:`advanced_neural_blackbox`.

``result.to_terminal(details=True)`` adds per-epoch measurements and the
dataset digest. ``result.plot(view="rounds")`` compares final and peak accuracy;
for a single experiment there is only one round point. The default epoch view
shows learning progress. For larger networks, see :doc:`advanced_neural_autond`.

Download :download:`the script <examples/advanced_neural_differential.py>`.
