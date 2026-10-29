Polynomial-system graphs: advanced
==================================

Compare round-local and cumulative growth using one retained system:

.. code-block:: python

   from claasp.primitives import Speck

   result = Speck(number_of_rounds=3).analysis.polynomial_system()
   result.to_terminal(cumulative=False)
   first_round = result.connection_graph(round_number=1)
   first_round.plot(show=False, save_to="round_1_connections.png")

``connection_graph()`` includes the whole system. ``round_number`` selects
only equations owned by that round, retaining variables shared with earlier
rounds. Nodes with no incidence in the selection are omitted. A larger graph
can reflect more intermediate variables or more equations; it is not by
itself a measure of algebraic security.

The returned immutable graph retains ``variables``, ``equations`` and
``edges`` without importing a plotting library. Its two-column layout labels
small graphs, hides labels above 60 nodes and requires at most 2,000 nodes.
Selecting a round keeps large systems readable. ``show=False`` and
``save_to=...`` control display and file output without rerunning the analysis.

See :doc:`advanced_algebraic_tests` for equation statistics, Boolean field
equations and bounded Gröbner experiments. Those computations use the same
system and have separate completion and timeout semantics.
