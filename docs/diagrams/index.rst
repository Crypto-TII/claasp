.. _diagram-guide:

Diagrams: ASCII, TikZ and state views
=====================================

Use ``Diagrams`` in the Sage-enabled Python environment where CLAASP is
installed. The object captures a primitive's typed native graph and provides
ASCII, TikZ, executable reconstruction and state views. Generation follows
operations and dependencies; primitive names do not select layouts.

Start with a small instance
---------------------------

This one-round Speck instance is a minimal API example, not the full-round
cipher. The following examples share the same ``cipher`` and ``diagram``::

    sage: from claasp.diagrams import Diagrams, from_ascii
    sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
    sage: cipher = SpeckBlockCipher(number_of_rounds=int(1))
    sage: diagram = Diagrams(cipher)
    sage: body = diagram.to_ascii()
    sage: isinstance(body, str)
    True

``print(body)`` displays the actual default picture:

.. literalinclude:: examples/speck1-persistent.asciiart
   :language: text

Exact import and executable reconstruction
------------------------------------------

Use annotated ASCII to retain native widths, ordered bit selections,
parameters, roles and round boundaries. Parsing follows the visible routes::

    sage: text = diagram.to_ascii(annotations=True)
    sage: from_ascii(text) == diagram.ir
    True
    sage: inputs = list(map(int, [0x6574694c, 0x1918111009080100]))
    sage: restored = diagram.to_cipher()
    sage: restored.evaluate(inputs) == cipher.evaluate(inputs)
    True

``diagram.ir`` returns an independent copy. Later edits to that dictionary or
the original cipher do not change the captured object. Reconstructed component
identifiers may differ; ``restored.diagram_source_ids`` maps original identities
to runtime identities. Bare pictures or pseudocode do not recover arbitrary
original placement without layout annotations.

Matching TikZ and generic states
--------------------------------

The default vector view renders the validated persistent ASCII placement::

    sage: fragment = diagram.to_tikz()
    sage: r'\begin{tikzpicture}' in fragment
    True

Insert the fragment in a LaTeX document that loads ``tikz``. Use
``pageBreaks=True`` for paginated panels or ``fitToPage=(25, 18)`` for a complete
overview in the given usable dimensions, in centimetres. Overview scaling
has no minimum-font guarantee.

Evaluated word states show the initial bank and native round boundaries::

    sage: values = diagram.evaluate_state_values(inputs)
    sage: frames = diagram.state_snapshots(mode='word', word_bits=None, values=values)
    sage: [len(frame['words']) for frame in frames]
    [6, 6]
    sage: state_fragment = diagram.state_tikz(mode='word', word_bits=None, values=values)
    sage: r'\begin{tikzpicture}' in state_fragment
    True

Set ``word_bits=None`` explicitly for word-width inference. Without explicit
geometry, states retain a generic flat-bank ambiguity. ``columns`` supplies a
row-major arrangement; it does not infer a cipher-specific matrix. Declared
and frontier state serialization support is separate from visual acceptance.

Supported shapes and explicit alternatives
------------------------------------------

Persistent views require an admitted aligned word graph. ``routed_words=True``
explicitly enables supported live-word copies and three-input Boolean gates.
Inline hexadecimal constants use the existing two-line glyph, with at most
fourteen label characters including ``x``. Mixed widths, larger arities and
other unsupported shapes still fail explicitly; work bounds reject oversized
requests rather than omit components.

For an explicit diagnostic representation use ``diagram.to_ascii(format='audit')``
or ``diagram.to_tikz(layoutSource='audit')``. The older exact manual serializer
is available through ``format='human-legacy'``. These choices do not imply
builder/UI admission or reconstruct an arbitrary original drawing.

Continue with :doc:`persistent_word_examples`, the
:doc:`Diagrams class reference <../cipher_modules/diagram/facade>` and the
:doc:`functional API reference <../cipher_modules/diagram/api>`.

.. toctree::
   :maxdepth: 2

   persistent_word_examples
