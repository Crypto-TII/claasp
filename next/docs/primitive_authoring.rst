Implementing a primitive
=========================

Primitive code should resemble the primitive's pseudocode. Whole ports can be
passed directly to components, indexing selects logical units, and component
identifiers are optional.

.. doctest::

   >>> from claasp_next import Primitive, PrimeField, ValueType
   >>> from claasp_next.components import Add, Permutation
   >>> field_vector = ValueType(PrimeField(17), (3,))
   >>> primitive = Primitive("small_permutation", {"state": field_vector})
   >>> state = primitive.input("state")
   >>> state[2, 0].positions
   (2, 0)
   >>> primitive.add_round()
   Round(number=0)
   >>> shuffled = primitive.add_component(Permutation(state, (2, 0, 1)))
   >>> shuffled.owner_id
   'permutation_0_0'
   >>> output = primitive.add_component(Add((shuffled, state)))
   >>> output.owner_id
   'add_0_1'
   >>> primitive.set_output(output)

Automatic identifiers combine the component kind, round number, and position,
so rebuilding the same graph produces the same names. Pass
``component_id="round_output"`` when a stable semantic name helps analysis or
documentation. Duplicate explicit names are rejected.

The ``claasp_next.utils`` module provides reusable finite-field arithmetic,
fixed-width rotation, and matrix-layout helpers. Primitive classes should contain
their round and key-schedule logic, not private copies of generic mathematics.
The AES implementation is the current full-size example.
