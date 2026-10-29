Impossible differentials: advanced
==================================

Choosing splits and boundaries
------------------------------

The automatic search tries each internal round boundary in order. Restrict it
when investigating a particular construction:

.. code-block:: python

   from claasp.primitives import Present

   primitive = Present(number_of_rounds=2)
   result = primitive.analysis.search_impossible_differentials(
       middle_round=1, limit=2,
   )
   result.to_terminal()

Each candidate retains the split, forward and backward characteristics, and
contradictory middle positions. ``input_pattern`` and ``output_pattern`` accept
MSB-first strings of ``0``, ``1`` and ``?`` for bitwise searches. Unspecified
external patterns are chosen by the solver. All non-active inputs have zero
difference by default; ``active_input`` and ``zero_difference_inputs`` expose
this policy explicitly.

Set ``split_order=(2, 1)`` to choose an order, or ``middle_round=1`` to search
one split. A finite ``limit`` stops after that many candidates. Candidate pairs
are blocked by external patterns, so auxiliary assignments do not generate
duplicate pairs at a split. The same external pair can occur at different
splits; those are separate checked explanations.

``complete`` means that the declared model search was exhausted with UNSAT.
``require_complete()`` rejects a limited or unknown run. Exhausting this
abstract propagation model without a contradiction does not establish that a
concrete differential is possible. Conversely, a checked bitwise contradiction
rules out the represented pair under the stated input-difference policy.

Coverage and wordwise searches
------------------------------

The bitwise model supports reversible Bit/Word graph slices with XOR,
permutations, rotations, constants, modular addition/subtraction and small
lookup substitutions. Lookup propagation uses the exact set of possible
output differences for each partial input pattern; tables up to eight input
bits are supported. Boolean AND/OR use a sound conservative abstraction.
Published round boundaries are required, and unsupported inverse rules fail
explicitly. PRESENT, Heys and ToySpeck now publish their round states for
these workflows.

``representation="wordwise"`` selects the existing four-state model for
suitable finite-domain graphs. Its candidates retain that model's abstract
interpretation and must not be promoted into new probability or concrete
security claims. Wordwise fixed patterns use typed ``WordwiseXorDifference``
values. The older ``find_impossible_xor_differential`` CP workflow remains
available for its documented Speck/Simon cases; it is separate from this
SAT orchestration.
