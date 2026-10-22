Introduction to basic primitive analysis
========================================

Explore what CLAASP can reveal about a primitive with short, runnable examples.
Each example starts with a concrete question, runs an analysis, and displays
its results as plots or tables. You can use a standard primitive, change the
round count, or adapt the example to your own design.

Before you begin
----------------

Follow :doc:`getting_started` to install CLAASP in a virtual environment. Its
full installation includes the Python dependencies used for plotting, tables,
and neural training throughout this section.

If you chose a core-only installation, add the extras needed for your analysis
from the repository root, with your virtual environment activated. The current
avalanche example needs the presentation extra:

.. code-block:: console

   python -m pip install -e '.[presentation]'

Getting started also lists the available extras for more selective installations.

Structure of an analysis script
-------------------------------

Every concrete section in this part of the guide follows the same sequence:

#. State the question and configure the primitive, analysis budget, and seed
   where randomness applies. State any empirical acceptance threshold.
#. Construct the primitive.
#. Run the analysis once and keep the returned ``result``.
#. Print the basic terminal report; request details only when investigating.
#. Choose a plot view, then optionally save it. Reporting reuses the result.

Use ``primitive`` and ``result`` consistently in examples. A runnable instance
of this template is:

.. code-block:: python

   from claasp.primitives import Speck

   # 1. Configuration
   rounds = 7
   samples = 1000
   seed = 9
   threshold = 0.01

   # 2. Primitive
   primitive = Speck(number_of_rounds=rounds)

   # 3. Analysis — run once
   result = primitive.analysis.avalanche(
       "plaintext", samples, seed=seed, threshold=threshold
   )

   # 4. Terminal report
   result.to_terminal()
   # result.to_terminal(details=True)  # Optional investigation

   # 5. Visualization and optional export
   result.plot()
   # result.plot(show=False, save_to="analysis.png")

The primitive constructor, analysis method, and its parameters change with the
question. Exact analyses need no sampling seed or empirical threshold. Plotting
is shown when the result supports a visualization. Subsequent sections should
follow this structure and provide a downloadable script exercised by CI.

Each section places the basic terminal output immediately after its command,
and each figure immediately after the command that produces it. Detailed
terminal output is available on request rather than reproduced in the guide.

Use the examples
----------------

Start with :doc:`basic_avalanche_analysis` to see how a one-bit input change
spreads through Speck and ChaCha, and how the resulting measurements can be
visualized.

Sample counts and seeds are stated explicitly so you can repeat an experiment
or increase its budget. Empirical measurements describe the sampled behavior;
they do not establish a primitive's security.

For detailed analysis options and result contracts, continue to the advanced
primitive analysis guides, starting with :doc:`analysis`.
