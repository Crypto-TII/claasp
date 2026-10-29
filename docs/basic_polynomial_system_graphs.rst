Polynomial-system graphs: introduction
======================================

A connection graph shows which variables occur in each polynomial equation.
This small substitution makes both sides easy to inspect:

.. plot::
   :include-source: True

   from claasp.primitives import BitVectorSBox

   primitive = BitVectorSBox(2, [0, 1, 3, 2])
   result = primitive.analysis.polynomial_system()
   result.connection_graph().plot()

Variable nodes are labelled ``v0``, ``v1``, ...; equation nodes are labelled
``e0``, ``e1``, .... An edge means the variable occurs in that equation. The
graph describes the local equation system, including intermediate variables,
rather than the fully expanded output ANFs.
