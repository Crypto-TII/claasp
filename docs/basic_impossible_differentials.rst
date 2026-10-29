Impossible differentials: introduction
======================================

Search for an input/output difference pair ruled out by a contradiction
between forward and backward propagation:

.. code-block:: python

   from claasp.primitives import Speck

   result = Speck(number_of_rounds=3).analysis.search_impossible_differentials()
   result.to_terminal()

The optional Kissat executable runs the SAT search. CLAASP tries internal
round splits and independently checks a returned model witness. The default
stops at one candidate, so it does not claim to enumerate every impossible
pair. The advanced guide explains fixed boundaries, enumeration and the
meaning of model exhaustion.
