Customizing AES
===============

Use ``AES`` when the graph should remain canonical AES, including a
reduced-round prefix or a different graph realization. Use ``CustomAES`` when
the mathematical construction itself changes. Keeping those classes separate
prevents an experimental result from being mistaken for a standard AES
result.

Available options
-----------------

``CustomAES`` accepts four constructor options:

``key_bit_size``
   Selects a 128-, 192-, or 256-bit key schedule. The default is 128.

``number_of_rounds``
   Selects a positive prefix of the standard round count for that key size:
   at most 10, 12, or 14 rounds respectively. Omitting it selects the full
   standard count.

``sbox_table``
   Replaces the AES S-box in both round SubBytes and SubWord in the key
   schedule. Supply 256 byte values. The default is the published AES S-box.

``include_mix_columns``
   Keeps or removes MixColumns from every round that would ordinarily contain
   it. The default is ``True``.

Key size and round count
------------------------

Constructor arguments are named so a study configuration remains readable:

.. doctest::

   >>> from claasp.primitives import CustomAES
   >>> study = CustomAES(key_bit_size=256, number_of_rounds=5)
   >>> study.details()
   Primitive details
     Type: block cipher
     Instance: CustomAES-256
     Inputs:
       plaintext: 128 bits (public)
       key: 256 bits (secret)
     Output: 128 bits
     Rounds: 5
     Realization: default

This is an AES-derived five-round study graph, not standard AES-256, which
uses 14 rounds.

Replace the S-box
-----------------

Start from the published table when only a few entries should change. This
example swaps two outputs and therefore keeps the table bijective:

.. doctest::

   >>> from claasp.primitives.block_ciphers.aes import AES_SBOX
   >>> custom_sbox = list(AES_SBOX)
   >>> custom_sbox[0], custom_sbox[1] = custom_sbox[1], custom_sbox[0]
   >>> changed_sbox = CustomAES(sbox_table=custom_sbox, number_of_rounds=2)
   >>> changed_sbox.provenance
   (('derived_from', 'AES'), ('modifications', 'replaced AES S-box in rounds and key schedule'))

CLAASP checks that component values have the required size. It does not claim
that a caller-supplied S-box is cryptographically suitable; that is part of
the experiment being defined.

Remove MixColumns
-----------------

Set ``include_mix_columns=False`` to omit MixColumns from the constructed
rounds:

.. doctest::

   >>> no_mix = CustomAES(include_mix_columns=False, number_of_rounds=2)
   >>> no_mix.provenance
   (('derived_from', 'AES'), ('modifications', 'removed MixColumns'))

The modification is recorded with the graph and remains visible to result and
serialization tooling.

Combine changes
---------------

The options compose. This graph uses a 256-bit key, five rounds, the modified
S-box above, and no MixColumns:

.. doctest::

   >>> combined = CustomAES(
   ...     key_bit_size=256,
   ...     number_of_rounds=5,
   ...     sbox_table=custom_sbox,
   ...     include_mix_columns=False,
   ... )
   >>> combined.details()
   Primitive details
     Type: block cipher
     Instance: CustomAES-256
     Inputs:
       plaintext: 128 bits (public)
       key: 256 bits (secret)
     Output: 128 bits
     Rounds: 5
     Realization: default
   >>> combined.provenance[1][1]
   'replaced AES S-box in rounds and key schedule; removed MixColumns'

Deeper structural changes
-------------------------

``CustomAES`` deliberately has a small constructor. Changing ShiftRows, the
MixColumns matrix, the order of round operations, or the key-schedule
structure requires an explicitly authored AES-derived graph. See
:doc:`composite_blocks` for reusable ``AESRound`` and ``AESKeySchedule``
blocks, then :doc:`primitive_authoring` for the graph-authoring workflow.
