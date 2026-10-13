Persistent word examples
========================

These tested minimal scripts use the ordinary default. Each picture keeps two
data words and four key words; carried key terminals are not additional cipher
outputs. Adding ``annotations=True`` keeps the exact same body and supplies the
packed-bit and native parameter bindings required by ``from_ascii``.

One round
---------

.. code-block:: python

    from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    from claasp.diagrams import from_cipher, to_ascii
    cipher = SpeckBlockCipher(number_of_rounds=1)
    ir = from_cipher(cipher)
    print(to_ascii(ir))

Actual output (no helper or observer boxes):

.. literalinclude:: examples/speck1-persistent.asciiart
   :language: text

Two rounds
----------

.. code-block:: python

    from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    from claasp.diagrams import from_cipher, to_ascii
    cipher = SpeckBlockCipher(number_of_rounds=2)
    ir = from_cipher(cipher)
    print(to_ascii(ir))

Actual output; the zero constant is an extra source outside the six primary lanes:

.. literalinclude:: examples/speck2-persistent.asciiart
   :language: text

Key side and vector counterpart
-------------------------------

``to_ascii(ir, key_side='left')`` relocates the key bank. First-use key word
ordering can differ between round counts; annotated native bit bindings retain
its actual identity. The matching vector view uses the same validated placement:

.. code-block:: python

    from claasp.diagrams import to_tikz
    fragment = to_tikz(ir, layoutSource='persistent', key_side='left')

Load TikZ in the surrounding LaTeX document. ``operator_style='labels'`` and
``wire_borders=True`` change vector styling; spacing and panel options change
presentation without changing the native bindings. No legacy helper tables are
added. Current builder native-footer admission remains open.

Unsupported shapes fail explicitly. Use ``format='human-legacy'`` to request the
old exact manual serializer, or ``layoutSource='human'`` for its historical TikZ
view. These are explicit compatibility choices, not default substitutes.
