Getting started
===============

Installation
------------

Install the development package from the repository's ``next`` directory:

.. code-block:: console

   python -m pip install -e .

No SageMath or solver is needed to construct and evaluate primitives.

Evaluate AES
------------

Inputs and outputs of traditional block ciphers are ordinary packed integers.
The primitive knows its block, key, unit sizes, and byte ordering.

.. doctest::

   >>> from claasp_next.primitives import AES
   >>> aes = AES()
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> ciphertext = aes.evaluate(plaintext, key)
   >>> f"{ciphertext:032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

Keyword and mapping forms are equivalent when explicit names are clearer:

.. doctest::

   >>> aes.evaluate(plaintext=plaintext, key=key) == ciphertext
   True
   >>> aes.evaluate({"plaintext": plaintext, "key": key}) == ciphertext
   True

Inspect an execution
--------------------

Ordinary evaluation returns only the result. Ask for a trace when debugging a
primitive or inspecting round values:

.. doctest::

   >>> one_round = AES(number_of_rounds=1)
   >>> trace = one_round.evaluate_with_trace(plaintext, key)
   >>> bytes(trace.value_of("sub_bytes_1")).hex()
   '63cab7040953d051cd60e0e7ba70e18c'
   >>> len(one_round.components) > 0
   True

Next steps
----------

- :doc:`primitive_authoring` shows concise components, indexing, automatic
  identifiers, and reusable mathematics.
- :doc:`analysis` introduces constraints, projections, key recovery, and
  optional solver backends.
- :doc:`traditional_primitives` covers AES, PRESENT, and Speck block-cipher
  variants.
- :doc:`whats_new_v5` explains typed units and native support for
  arithmetization-oriented primitives.
