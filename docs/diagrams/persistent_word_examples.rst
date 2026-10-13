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
    fragment = to_tikz(ir, key_side='left')

Load TikZ in the surrounding LaTeX document. ``operator_style='labels'`` and
``wire_borders=True`` change vector styling; spacing and panel options change
presentation without changing the native bindings. No legacy helper tables are
added. Current builder native-footer admission remains open.

Unsupported shapes fail explicitly. Use ``format='human-legacy'`` to request the
old exact manual serializer, or ``layoutSource='human'`` for its historical TikZ
view. These are explicit compatibility choices, not default substitutes.


Persistent vector defaults and overview
--------------------------------------

Bare ``to_tikz(ir)`` uses the reparsed persistent word placement. Diagnostic
views/tables require explicit ``layoutSource='audit'``. Unsupported persistent
shapes fail with that explicit alternative; they are never silently substituted.
MODSUB input arrows are numbered 1 and 2, meaning operand 1 minus operand 2.
Continuation panels balance the global rows, preserving all cells and paired
route identifiers. ``fitToPage=(25,18)`` uses one complete figure, uniformly
scaled to the given usable width and height in centimetres. Small text in a
large overview is a readability tradeoff; paginated detail remains available.

Generic word-state progression
------------------------------

.. code-block:: python

    from claasp.diagrams import evaluate_state_values, state_snapshots, state_tikz
    values = evaluate_state_values(cipher, [0x6574694c, 0x1918111009080100])
    frames = state_snapshots(ir, mode='word', word_bits=None, values=values)
    fragment = state_tikz(ir, mode='word', word_bits=None, values=values,
                          cell_width=1.8, page_breaks=False)

Word mode tracks the same generic persistent lanes, their actual producer bits,
and data/key roles. Initial state and every native round boundary are shown;
intra-round steps are explicitly labelled omitted. ``granularity='operation'``
shows the initial state and every visible native word operation, including
unchanged lane banks when an operation produces a temporary value. Constants
are parameters, not state updates. This is a lane bank, not an inferred
algorithmic state matrix. With no shape annotation the fallback is a flat bank;
``columns=4`` explicitly arranges sixteen words into four columns. Source order
means the persistent bank's actual first-use order; key packing may differ
between round counts. ``order='reverse'`` reverses words while retaining each
word's bit order. Declared observation and dependency-frontier modes retain
their previous diagnostic meaning.

Reproduce the evaluated Speck, ChaCha, both subtraction orders, balanced
continuations and full overview PDFs using ``examples/render_word_states.py``.
The script needs Sage-enabled Python, TikZ/pdflatex and Poppler; it writes into
an explicitly supplied output directory. No primitive name selects a layout.
