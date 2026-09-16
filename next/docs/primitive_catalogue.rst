Primitive catalogue
===================

The public catalogue contains every fixed-length primitive tracked by the v5
migration inventory. Classes are available from ``claasp_next.primitives`` for
ordinary use and from semantic category modules when the distinction matters:

* ``block_ciphers`` and ``tweakable_block_ciphers`` are keyed permutations;
* ``permutations`` are unkeyed permutations;
* ``block_functions`` are keyed fixed-length mappings that need not be
  permutations;
* ``functions`` are unkeyed fixed-length mappings;
* ``single_component_primitives`` and ``toy_primitives`` are explicit
  analysis and teaching fixtures.

The categories describe mathematical interfaces, not execution engines.
Graph realizations remain separate from scalar, batch, and constraint
representations.

Importing and evaluating a catalogue primitive
----------------------------------------------

Top-level imports are intentionally short. This reduced-round Ascon instance
is still the same 320-bit permutation family:

.. doctest::

   >>> from claasp_next.primitives import Ascon
   >>> ascon = Ascon(number_of_rounds=4)
   >>> len(ascon.rounds)
   4
   >>> f"{ascon.evaluate(0):080x}"[:16]
   '6e5a585776456145'

The category import resolves to the identical class, which is useful for
catalogue browsers and type-directed applications:

.. doctest::

   >>> from claasp_next.primitives.permutations import Ascon as CategorizedAscon
   >>> CategorizedAscon is Ascon
   True

Audited parameter sets are explicit. A generated catalogue graph accepts only
combinations present in its primitive-owned index, so a typo or unsupported
combination cannot silently select a different graph:

.. doctest::

   >>> Ascon(number_of_rounds=5)
   Traceback (most recent call last):
   ...
   ValueError: unsupported ascon parameter combination; ...

Primitive-owned data
--------------------

Primitives with multiple realizations, parameter sets, generated constants,
or supporting data use a same-import-path package. Poseidon, for example,
owns ``primitive.py``, ``parameters.py``, and its versioned ``data/`` directory.
The convenience namespace remains available:

.. doctest::

   >>> from claasp_next.parameters import poseidon_bn254_width3
   >>> from claasp_next.primitives.permutations.poseidon import (
   ...     poseidon_bn254_width3 as owned_poseidon_parameters)
   >>> poseidon_bn254_width3() is owned_poseidon_parameters()
   True

Frozen graph files are package implementation data. Users should construct the
public class and inspect its immutable typed graph instead of parsing those
files directly.
