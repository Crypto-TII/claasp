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

Use the examples
----------------

Start with :doc:`basic_avalanche_analysis` to see how a one-bit input change
spreads through Speck and ChaCha, and how the resulting measurements can be
visualized.

The examples include downloadable Python scripts. The same code generates the
figures in this guide and is exercised in CI with small, reproducible inputs.
Sample counts and seeds are stated explicitly so you can repeat an experiment
or increase its budget. Empirical measurements describe the sampled behavior;
they do not establish a primitive's security.

For detailed analysis options and result contracts, continue to the advanced
primitive analysis guides, starting with :doc:`analysis`.
