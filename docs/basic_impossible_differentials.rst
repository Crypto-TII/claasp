Impossible differentials: introduction
======================================

**What is an impossible differential?**

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

From the result above it is possible to see that with the 6-round version of Speck there is an impossible differential happening in the second middle round. The contradiction happens because ``0b??????????100000??????????1000??`` and ``0b????????????????????????100?????`` differ for at least one bit in the 26-th position.

It is also possible to plot the result in order to see the same information visually.

.. plot::
   :context: close-figs
   :include-source:

   result.plot()