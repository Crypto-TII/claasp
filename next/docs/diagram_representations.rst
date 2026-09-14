Diagram representations and renderers
=====================================

A primitive diagram is a representation of the typed graph, not a property of a
solver. ``DiagramCompiler`` preserves component IDs, logical-unit selections,
input ordering, rounds, and optional graph annotations in ``PrimitiveDiagram``.
The temporary ASCII listing and TikZ serializer are independent views over
that immutable IR.

.. warning::

   ``ASCIIArtSerializer`` is a work in progress. It currently emits a
   line-oriented structural listing and an ``ASCIIArtWorkInProgressWarning``;
   box layout and connector routing remain to be integrated from the dedicated
   ASCII-art compiler work. The diagram IR and TikZ serializer are not marked
   experimental by this limitation.

This separation lets the same concrete execution trace, cryptanalytic trail,
or side-channel annotation be displayed without teaching a renderer its
semantics. New serializers should consume ``PrimitiveDiagram``; they should not
walk a ``Primitive`` independently or invoke an analysis backend.

.. doctest::

   >>> from claasp_next.primitives import MiMC
   >>> from claasp_next.representations.diagrams import DiagramCompiler
   >>> primitive = MiMC(17, 3, (1,))
   >>> diagram = DiagramCompiler().compile(primitive)
   >>> diagram.primitive_name
   'mimc'
   >>> [group.number for group in diagram.rounds]
   [0]
   >>> {node.kind for node in diagram.nodes} >= {'input', 'output'}
   True

The convenient ``Primitive.diagram()`` method accepts a ``GraphAnnotation``, an
``ExecutionTrace``, a ``SideChannelTrace``, or a trail object exposing
``annotate(primitive)``. ``Primitive.draw()`` then selects a serializer.

.. doctest::

   >>> trace = primitive.evaluate_with_trace(5).trace
   >>> annotated = primitive.diagram(trace)
   >>> all(node.annotation is not None for node in annotated.nodes)
   True
   >>> text = primitive.draw("ascii", trace)
   >>> "round 0" in text and "#" in text
   True
   >>> latex = primitive.draw("tikz", trace)
   >>> latex.startswith(r"\documentclass{article}")
   True

PDF rendering is deliberately optional. ``primitive.draw("pdf")`` passes the
TikZ document to ``LaTeXDriver`` and returns PDF bytes. It raises
``FileNotFoundError`` when ``pdflatex`` is unavailable. The core, ASCII, and
TikZ paths remain dependency-free; a dedicated integration test exercises the
external renderer.

API reference
-------------

.. automodule:: claasp_next.representations.diagrams
   :members:

.. automodule:: claasp_next.drivers.renderers
   :members:
