Impossible differentials: introduction
======================================

**What is an impossible differential cryptanalysis?**

Given a block cipher :math:`E : \mathbb{F}_2^{n} \times \mathbb{F}_2^{k} \to \mathbb{F}_2^{n}`, differential cryptanalysis studies how a specific input difference :math:`\delta` propagates to an output difference :math:`\gamma` through the cipher. More precisely, an attacker is interested in pairs :math:`(\delta, \gamma)` such that :math:`E_K(X) \oplus E_K(X \oplus \delta) = \gamma` holds with a high probability over all keys :math:`K` and plaintexts :math:`X`.

Conversely, **impossible differential cryptanalysis** focuses on differentials with probability :math:`0` an impossible differential for :math:`E` is a pair :math:`(\delta, \gamma)` such that:
    .. math:: E_K(X) \oplus E_K(X \oplus \delta) \neq \gamma
for all keys :math:`K` and plaintexts :math:`X`.

Let's try an example with a 6-round version of SPECK32-64 in CLAASP.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=6)
   result = primitive.analysis.search_impossible_differentials()

NOTE: By default the method ``search_impossible_differentials()`` uses Kissat, so the ``kissat`` executable must be installed and on your ``PATH``.

Print the outcome:

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
   Path("_build/impossible_differentials_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/impossible_differentials_basic_terminal.txt
   :language: text

The search splits the cipher at each internal round boundary in turn, starting after round 1, and stops at the first boundary where it finds a contradiction.
The table shows the round after which that contradiction occurs. The search stops there because it returns one candidate by default, so ``result.found`` is ``True`` but ``result.complete`` is ``False``: a single candidate says nothing about whether other differentials exist.

The candidate holds the pair of difference patterns that cannot be connected. Patterns are written most significant bit first with the symbols ``0``, ``1`` and ``?``, where ``?`` is a bit that may take either value. A SPECK32/64 block is two 16-bit words, so the code below prints each pattern as two halves:

.. code-block:: python

   trail = result.candidates[0].trail
   input_pattern = str(dict(trail.forward.input_patterns)["plaintext"])
   output_pattern = str(dict(trail.backward.input_patterns)["output"])

   print("input :", input_pattern[:16], input_pattern[16:])
   print("output:", output_pattern[:16], output_pattern[16:])

.. plot::
   :context:
   :nofigs:
   :include-source: false

   trail = result.candidates[0].trail
   input_pattern = str(dict(trail.forward.input_patterns)["plaintext"])
   output_pattern = str(dict(trail.backward.input_patterns)["output"])

   output = StringIO()
   print("input :", input_pattern[:16], input_pattern[16:], file=output)
   print("output:", output_pattern[:16], output_pattern[16:], file=output)
   Path("_build/impossible_differentials_basic_patterns.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/impossible_differentials_basic_patterns.txt
   :language: text

No pair of plaintexts whose difference matches the input pattern can encrypt, under the same key, to a pair of ciphertexts whose difference matches the output pattern. The key difference is fixed to zero and the plaintext difference is the one the search chooses.

To see why, look at where the two patterns meet:

.. code-block:: python

   boundary = trail.boundary
   print("forward :", boundary.forward)
   print("backward:", boundary.backward)
   print("contradiction at position(s):", boundary.contradictory_positions)

.. plot::
   :context:
   :nofigs:
   :include-source: false

   boundary = trail.boundary

   output = StringIO()
   print("forward :", boundary.forward, file=output)
   print("backward:", boundary.backward, file=output)
   print("contradiction at position(s):", boundary.contradictory_positions, file=output)
   Path("_build/impossible_differentials_basic_boundary.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/impossible_differentials_basic_boundary.txt
   :language: text

The forward pattern is what the input difference is guaranteed to look like at the split after propagating through the first rounds. The backward pattern is what the output difference is guaranteed to look like at the same place after propagating back through the remaining rounds. Bits shown as ``0`` or ``1`` are certain; ``?`` bits are unknown. At each listed position, counted from the left of the pattern starting at 0, one side requires a ``1`` and the other a ``0``. Both cannot hold at once, so the differential is impossible.

The same process can be used to show that, increasing the number of rounds, an impossible differential cannot be found through this method.

.. plot::
   :context: close-figs
   :nofigs:
   :include-source:

   primitive = Speck(number_of_rounds=7)
   result = primitive.analysis.search_impossible_differentials()
   result.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   output = StringIO()
   result.to_terminal(file=output)
   Path("_build/impossible_differentials_basic_seven_rounds.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/impossible_differentials_basic_seven_rounds.txt
   :language: text

This time the search tried every internal round boundary and the solver proved that none of them can produce a contradiction, so ``result.found`` is ``False`` and ``result.complete`` is ``True``. The termination message ``exhausted UNSAT`` distinguishes this proof from the ``candidate limit`` stop above.

The proof applies to the model the search uses: the plaintext is active, the key difference is zero, and differences are bitwise ``0``, ``1`` and ``?`` patterns. It shows that this search finds no 7-round impossible differential, not that no other method could find one.