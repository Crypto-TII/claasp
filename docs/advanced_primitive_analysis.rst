Introduction to advanced primitive analysis
===========================================

Each analysis introduced in :doc:`basic_primitive_analysis` has a corresponding
advanced guide. Start with :doc:`advanced_avalanche_analysis` for avalanche tests.

The basic pages answer one question with a short script using defaults. Here,
we explore analysis and test parameters, explain the measured quantities and
criteria, and compare ways of reporting the results.

Structure of an advanced analysis script
----------------------------------------

Construct the primitive and select the experiment's inputs and parameters.
Run the analysis and keep its result. Then inspect detailed reports, compute
derived quantities, compare views, or export the retained data. Reporting a
stored result should reuse the measurement wherever the analysis permits it.

State sample counts and seeds for randomized experiments, solver limits for
searches, and training settings for neural experiments. Explain thresholds in
their actual units and distinguish empirical observations from exact results.
A graph or export task can follow this structure without inventing sampling
parameters or terminal reports.

Each advanced page links back to its basic example. Displayed commands are
followed immediately by their output or figure, and downloadable companion
scripts are exercised in CI.
