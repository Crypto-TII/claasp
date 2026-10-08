Getting started
===============

Installation
------------

CLAASP requires Python 3.11 or later. From the repository root, create a
virtual environment and install the package:

.. code-block:: console

   python -m venv .venv
   source .venv/bin/activate
   python -m pip install -e .

On Windows PowerShell, activate the environment with
``.venv\Scripts\Activate.ps1`` instead. Confirm that Python imports the
installed package:

.. code-block:: console

   python -c "import claasp; print('CLAASP import OK')"

Evaluation and avalanche experiments need no external program. The trail
search later on this page also needs the optional Kissat executable; its
installation is described where it is first used.

Choose a primitive
------------------

Ready-to-use primitives have short imports from ``claasp.primitives``. Start
with the standard AES-128 configuration. In an interactive Python shell or
notebook, type ``aes.`` and press Tab to discover its available operations;
``details()`` gives a compact description of the selected instance:

.. doctest::

   >>> from claasp.primitives import AES
   >>> aes = AES()
   >>> aes.details()
   Primitive details
     Type: block cipher
     Instance: AES-128
     Inputs:
       plaintext: 128 bits (public)
       key: 128 bits (secret)
     Output: 128 bits
     Rounds: 10
     Realization: lookup

The constructor builds a reusable description of AES; it does not encrypt
anything yet. Constructor arguments can select another standard parameter set
or a reduced number of rounds. See :doc:`traditional_primitives` for common
block ciphers and :doc:`primitive_catalogue` for discovery and the full
catalogue.

Change the parameters
^^^^^^^^^^^^^^^^^^^^^

Pass constructor arguments by name so the choices remain readable. This
builds a five-round AES-256 study instance with the algebraic realization of
SubBytes:

.. doctest::

   >>> aes256 = AES(
   ...     key_bit_size=256,
   ...     number_of_rounds=5,
   ...     realization="algebraic",
   ... )
   >>> aes256.details()
   Primitive details
     Type: block cipher
     Instance: AES-256
     Inputs:
       plaintext: 128 bits (public)
       key: 256 bits (secret)
     Output: 128 bits
     Rounds: 5
     Realization: algebraic

Five rounds form a reduced prefix for analysis; standard AES-256 uses 14
rounds. AES currently provides ``lookup`` and ``algebraic`` realizations, not
a bitsliced realization.

Replace the S-box
^^^^^^^^^^^^^^^^^

Use ``CustomAES`` for an experimental change so results cannot be confused
with canonical AES. Here the first two entries of a copy of the AES S-box are
swapped, and the replacement is used in both SubBytes and the key schedule:

.. doctest::

   >>> from claasp.primitives import CustomAES
   >>> from claasp.primitives.block_ciphers.aes import AES_SBOX
   >>> custom_sbox = list(AES_SBOX)
   >>> custom_sbox[0], custom_sbox[1] = custom_sbox[1], custom_sbox[0]
   >>> custom = CustomAES(
   ...     sbox_table=custom_sbox,
   ...     key_bit_size=256,
   ...     number_of_rounds=5,
   ... )
   >>> custom.details()
   Primitive details
     Type: block cipher
     Instance: CustomAES-256
     Inputs:
       plaintext: 128 bits (public)
       key: 256 bits (secret)
     Output: 128 bits
     Rounds: 5
     Realization: default

``CustomAES`` also accepts ``include_mix_columns=False`` for studies that
remove MixColumns. See :doc:`composite_blocks` for the reusable AES blocks and
the provenance recorded for experimental modifications.

Evaluate AES
------------

Supply one value for each named input and evaluate a standard test vector:

.. doctest::

   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> ciphertext = aes.evaluate(plaintext=plaintext, key=key)
   >>> f"{ciphertext:032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

``evaluate`` returns the encoded output as a Python integer. Formatting it to
32 hexadecimal digits preserves leading zeroes and makes the 128-bit result
easy to compare with a published vector. Other traditional block ciphers use
the same packed-integer convention. Named arguments make the input order
explicit; positional arguments are also accepted in the order reported by
``aes.inputs()``.

Find a differential trail
-------------------------

A differential trail follows an XOR difference through each round of a
primitive. CLAASP can search for the lowest-weight—and therefore most
probable—trail in its differential model.

This example deliberately uses two-round Speck32/64 so the search finishes
quickly. It is a reduced-round analysis target, not a secure block-cipher
configuration. The default search uses the optional Kissat SAT solver. On
macOS or Linux with Homebrew, install it and confirm that it is on ``PATH``:

.. code-block:: console

   brew install kissat
   kissat --version

On other systems, build Kissat from its official source distribution. Then
run the search:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> speck = Speck(number_of_rounds=2)
   >>> result = speck.analysis.find_trail(kind="xor_differential")

``result`` is a ``TrailSearchResult``: it contains the mathematical trail and
the evidence for the search claim. Inspect the stable fields directly:

.. doctest::

   >>> result.trail.kind.value
   'xor_differential'
   >>> (result.trail.total_weight, result.lower_bound, result.is_optimal)
   (1.0, 1.0, True)
   >>> (result.metadata.solver, len(result.component_transitions))
   ('Kissat', 10)

Read those values as follows:

* ``total_weight`` is :math:`-\log_2(p)` for this one trail. Weight 1
  therefore represents trail probability :math:`p=2^{-1}` in the model.
* ``lower_bound`` is the proved minimum. Because it equals the trail weight,
  ``is_optimal`` is true: no lower-weight trail exists for this instance.
* ``component_transitions`` contains the ten checked rotations, modular
  additions, and XOR operations on the two-round data path.
* ``metadata`` records how the search was performed. Runtime and peak memory,
  when available, depend on the machine.

For an interactive, human-readable report, use:

.. doctest::

   >>> result.show()  # doctest: +ELLIPSIS
   Trail
   ...

The report's input and output are XOR differences, not plaintext and
ciphertext values. Its exact-ratio column gives each local transition
probability; the weights add while those probabilities multiply. The default
search fixes the key difference to zero, so the all-zero key-schedule
propagation is omitted. Another supported solver may return different input
and output differences with the same optimal weight.

See :doc:`analysis` when you need constraints or explicit backend and solver
selection. See :doc:`displaying_results` for Markdown, CSV, and structured
report output.

Measure avalanche behavior
--------------------------

An avalanche experiment changes one plaintext bit at a time and measures how
many output bits change. Fixing the key and seed makes the experiment
reproducible:

.. doctest::

   >>> avalanche = speck.analysis.avalanche(
   ...     "plaintext", 8, seed=9, fixed_inputs={"key": 0}
   ... )
   >>> avalanche.input_bit_count, avalanche.output_bit_count
   (32, 32)
   >>> round(sum(avalanche.mean_changed_output_bits) / 32, 2)
   9.47

Eight samples keep this introductory example quick. Use more samples before
drawing conclusions about a primitive; an avalanche result is experimental
evidence, not a proof.

More quick analyses
-------------------

See :doc:`quick_analysis_scripts` for short examples that find a linear trail,
generate data for a neural distinguisher, inspect AES round values, and repeat
the analyses above with explanations of their results.
