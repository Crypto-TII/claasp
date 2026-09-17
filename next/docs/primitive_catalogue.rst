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

Primitive kinds and input visibility
------------------------------------

Each graph states its mathematical interface separately from its execution
engine. Inputs also carry a semantic role and a default visibility. Keys are
secret by default, while plaintexts, states, tweaks, and nonces are public:

.. doctest::

   >>> from claasp_next import InputVisibility, PrimitiveKind
   >>> from claasp_next.primitives import AES
   >>> aes = AES()
   >>> aes.kind is PrimitiveKind.BLOCK_CIPHER
   True
   >>> aes.secret_inputs
   ('key',)
   >>> aes.input_descriptor("plaintext").visibility is InputVisibility.PUBLIC
   True

Visibility describes a study, not the value or the graph. A known-key study
can therefore derive new metadata without rebuilding or mutating AES:

.. doctest::

   >>> known_key = aes.with_input_visibility(key="public")
   >>> known_key.secret_inputs
   ()
   >>> aes.secret_inputs
   ('key',)

Custom authors may use ``public_input`` and ``secret_input`` when conventional
boundary names are not sufficient. Analyses may override the defaults again
for a particular experiment.

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

Constructor parameters build the graph from readable source. Reduced-round
study variants therefore do not depend on a pre-exported graph file:

.. doctest::

   >>> len(Ascon(number_of_rounds=5).rounds)
   5

The implementation is ordinary Python in
``claasp_next/primitives/permutations/ascon/primitive.py``. Twofish and WARP likewise
live in ``block_ciphers/twofish.py`` and ``block_ciphers/warp.py``; their round
functions and key schedules can be read directly rather than reconstructed
from serialized component records.

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

Simple primitives remain single modules. A family package co-locates alternate
realizations without changing the canonical import path. For example,
``permutations.keccak`` contains ``primitive.py``, ``sbox.py``, and
``invertible.py``; ``block_ciphers.tinyjambu`` contains its canonical, word,
and feedback-register realizations. AES uses a package for reusable blocks and
multiple realizations, LowMC for vetted constant files, and Poseidon for its
typed parameter catalogue and licensed data. Simon, Simeck, and Gimli S-box
forms are labelled legacy-regression realizations, not descriptions of their
canonical specifications. There are no runtime frozen-graph indexes or
compressed graph specifications.
