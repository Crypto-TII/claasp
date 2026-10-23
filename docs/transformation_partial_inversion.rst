Partial inversion and retained values
=====================================

Partial inversion states both the target and the known graph boundaries. In
this example, the right operand is retained while the left operand is
recovered from an XOR output:

.. doctest::

   >>> from claasp import PrimitiveBuilder, UnitArrayType, partial_inverse
   >>> from claasp.components import Xor
   >>> from claasp.unit_types import Word
   >>> builder = PrimitiveBuilder("mix", {
   ...     "left": UnitArrayType(Word(8), (1,)),
   ...     "right": UnitArrayType(Word(8), (1,)),
   ... })
   >>> _ = builder.add_round()
   >>> mixed = builder.add_component(Xor(builder.inputs()))
   >>> graph = builder.build(mixed)
   >>> recovery = partial_inverse(
   ...     graph,
   ...     graph.graph.input("left"),
   ...     known={"output": graph.graph.output, "right": graph.graph.input("right")},
   ... ).primitive
   >>> recovery.evaluate(0xA5, 0x3C)
   153

Known boundaries may also be intermediate selections. Equivalent recovered
wires are reused directly, without solver calls or identity placeholders.
