Getting started
===============

Install CLAASP
--------------

CLAASP requires Python 3.11 or later. From the repository root, create a
virtual environment and install the package:

.. code-block:: console

   python -m venv .venv
   source .venv/bin/activate
   python -m pip install -e .

On Windows PowerShell, activate the environment with
``.venv\Scripts\Activate.ps1``. Confirm that the installation works with:

.. code-block:: console

   python -c "import claasp; print('CLAASP import OK')"

Choose a primitive
------------------

Ready-to-use primitives have short imports from ``claasp.primitives``.
``details()`` summarizes the selected configuration:

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

In an interactive Python shell or notebook, type ``aes.`` and press Tab.
Routine operations stay on ``aes``; analysis, read-only structure, and
copy-producing transformations are grouped under ``aes.analysis``,
``aes.graph``, and ``aes.edit``.

:doc:`Want to know more about choosing and customizing primitives? <traditional_primitives>`
That guide shows official instances, constructor parameters, realizations,
reduced-round configurations, and links to S-box replacement and other AES
customizations.

Implement a primitive
---------------------

A primitive is a typed graph. This one-round example implements a fixed-size
one-time pad with one XOR component. Change ``bit_size`` to build another
message and key size:

.. doctest::

   >>> from claasp import PrimitiveBuilder, ValueType, Word
   >>> from claasp.components import Xor
   >>> bit_size = 128
   >>> value_type = ValueType(domain=Word(bit_size), shape=(1,))
   >>> builder = PrimitiveBuilder(
   ...     "one_time_pad",
   ...     {"message": value_type, "key": value_type},
   ...     kind="block_cipher",
   ...     instance_name=f"OneTimePad-{bit_size}",
   ... )
   >>> builder.add_round()
   Round(number=0)
   >>> ciphertext = builder.add_component(Xor(builder.inputs()))
   >>> one_time_pad = builder.build(ciphertext)
   >>> one_time_pad.details()
   Primitive details
     Type: block cipher
     Instance: OneTimePad-128
     Inputs:
       message: 128 bits (public)
       key: 128 bits (secret)
     Output: 128 bits
     Rounds: 1
     Realization: default

See :doc:`primitive_authoring` for rounds, component selection, intermediate
states, finite-field operations, and complete primitive classes.

Evaluate a cipher
-----------------

Supply one value for each named input. CLAASP accepts packed Python integers
at ordinary binary cipher boundaries:

.. doctest::

   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> ciphertext = aes.evaluate(plaintext=plaintext, key=key)
   >>> f"{ciphertext:032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

:doc:`Want to know more about evaluating primitives? <batch_evaluation>`
That guide covers several plaintexts with shared or separate keys, logical-unit
inputs, non-binary field values, and the lower-level batch evaluators.

Find an optimal differential trail
----------------------------------

An XOR-differential trail follows an input difference through each round.
This reduced-round Speck example finds the lowest-weight trail and proves that
no better trail exists:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> speck = Speck(number_of_rounds=3)
   >>> result = speck.analysis.find_optimal_trail()
   >>> (result.trail.total_weight, result.is_optimal)
   (3.0, True)

:doc:`Want to know more about searching for trails? <analysis>`
That guide explains trail kinds, input constraints, backend and solver
selection, result fields, probabilities, and supported primitive structures.

Display the trail
-----------------

``show()`` prints only the round boundaries and their relative and cumulative
probabilities by default:

.. doctest::

   >>> result.show()
   Trail
   <BLANKLINE>
   Round trail
   <BLANKLINE>
   Round | Difference | Relative probability | Cumulative probability
   ------+------------+----------------------+-----------------------
   input | 0x00400000 |                  1/1 |                    1/1
       1 | 0x80008000 |                  1/1 |                    1/1
       2 | 0x81008102 |                  1/2 |                    1/2
       3 | 0x8000840a |                  1/4 |                    1/8
   <BLANKLINE>
   Proved optimal.
   <BLANKLINE>
   Total weight: 3.

:doc:`Want to know more about displaying a trail? <displaying_results>`
That guide covers ``show(details=True)``, structured report data, and terminal,
Markdown, and CSV output.
