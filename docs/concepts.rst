Core concepts
=============

This page introduces the small set of ideas that appear throughout CLAASP.
A primitive is described once as a typed graph. The same graph can then be
evaluated, inspected, transformed, or translated for an analysis backend.

Primitives and graphs
---------------------

A *primitive* is a fixed computation such as AES, a reduced-round Speck
instance, or a permutation. Its graph has named inputs, an output, and an
ordered collection of operations called components. An edge in the graph
means that the output of one operation is used by another.

Constructing a primitive builds this description; it does not evaluate it:

.. doctest::

   >>> from claasp.primitives import AES
   >>> aes = AES(number_of_rounds=2)
   >>> aes.graph.input("plaintext").owner_id
   'plaintext'
   >>> aes.graph.input("key").owner_id
   'key'
   >>> len(aes.graph.round_outputs)
   2
   >>> len(aes.graph.components) > 0
   True

Domains
-------

A *domain* defines what one scalar value means and which operations are valid
for it. The Python integer ``0x57`` could encode an unsigned byte, a vector of
bits, or an element of :math:`GF(2^8)`; multiplication has a different meaning
in each case.

.. doctest::

   >>> from claasp import BinaryExtensionField, PrimeField, Word
   >>> aes_field = BinaryExtensionField(8, 0x11B)
   >>> aes_field.encoded_bit_size
   8
   >>> PrimeField(257).contains(256)
   True
   >>> PrimeField(257).contains(257)
   False
   >>> Word(8).contains(0x57)
   True

``Word(8)`` and ``BinaryExtensionField(8, 0x11B)`` both use eight bits when
encoded, but they do not have the same algebra. A word supports operations
such as integer addition modulo :math:`2^8` and rotation. A field element
supports polynomial-basis field arithmetic.

Value types
-----------

``ValueType`` describes the values carried by a graph wire. It combines:

* a ``domain`` for each scalar unit; and
* a ``shape`` giving the dimensions of the collection of units.

Use keyword arguments when introducing a value type so that both parts are
visible:

.. doctest::

   >>> from claasp import ValueType
   >>> vector = ValueType(domain=PrimeField(257), shape=(4,))
   >>> vector.unit_count
   4
   >>> vector.encoded_bit_size
   36

For the common boundary type consisting of one packed string of individual
bits, ``BitWord(size)`` is a concise spelling:

.. doctest::

   >>> from claasp import Bit, BitWord
   >>> BitWord(128) == ValueType(domain=Bit(), shape=(128,))
   True

This is different from ``ValueType(domain=Word(128), shape=(1,))``: the latter
declares one arithmetic word for word-level rotation and modular addition.

The comma in ``(4,)`` is Python's syntax for a one-element tuple. Without the
comma, ``(4)`` is just the integer ``4``. The tuple is needed because a shape
may have more than one dimension:

.. doctest::

   >>> matrix = ValueType(domain=PrimeField(257), shape=(3, 4))
   >>> matrix.shape, matrix.unit_count
   ((3, 4), 12)

The shape is logical rather than a nested Python container. Runtime values are
passed as an ordered flat tuple of scalar units; the shape records how an
author or backend should understand those units.

Ports and selections
--------------------

A *port* is a named graph input or component output. A *selection* chooses
logical units from a port. Positions refer to whole domain elements, not to
implicit bits, and their order is preserved.

.. doctest::

   >>> from claasp import Port
   >>> state = Port("state", vector)
   >>> selected = state[3, 1]
   >>> selected.positions
   (3, 1)
   >>> selected.value_type.unit_count
   2

Components and rounds
---------------------

A *component* is one operation, for example an XOR, an S-box, a rotation, or
a field multiplication. Components are immutable descriptions: execution and
solver behavior lives in separate backends. A *round* groups components in a
way that follows the primitive's specification and makes intermediate states
easy to find. It does not change the mathematics of the graph.

If a backend does not support a component, it raises an error instead of
silently changing the operation or decomposing it into bits.

Joining graph wires
-------------------

Joining values is structural wiring, not a cryptographic operation. Pass a
sequence directly as a primitive output, or use ``join`` when a later
operation needs one combined value. Homogeneous units remain in the supplied
order.

.. doctest::

   >>> from claasp import PrimitiveBuilder
   >>> pair = ValueType(domain=PrimeField(257), shape=(2,))
   >>> builder = PrimitiveBuilder("wiring", {"left": pair, "right": pair})
   >>> builder.add_round()
   Round(number=0)
   >>> state = builder.join(builder.input("left"), builder.input("right")[1, 0])
   >>> wiring = builder.build(state)
   >>> wiring.evaluate((1, 2), (3, 4))
   (1, 2, 4, 3)

CLAASP records a multi-source join as typed wiring that traces, diagrams, and
constraint models can follow. A single-source ``join`` adds no new binding.

Realizations and execution engines
----------------------------------

A *realization* is one graph that implements a primitive. Two realizations
have the same named inputs and mathematical output but expose different
internal operations. For example, AES can represent SubBytes as a lookup
table or as field inversion followed by an affine map:

.. doctest::

   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> lookup = AES(realization="lookup")
   >>> algebraic = AES(realization="algebraic")
   >>> lookup.evaluate(plaintext, key) == algebraic.evaluate(plaintext, key)
   True
   >>> [item.name for item in AES.available_realizations()]
   ['lookup', 'algebraic']

Choose a realization explicitly when its internal structure matters, or ask
CLAASP for one with the capability required by an analysis:

.. doctest::

   >>> AES.for_capabilities({"sbox_semantics"}).realization.name
   'lookup'
   >>> AES.for_capabilities({"algebraic_semantics"}).realization.name
   'algebraic'

An *execution engine* is different: it evaluates an already chosen graph.
Scalar and batch Python evaluators are execution engines, not realizations.
Results record both identities so an experiment can be reproduced.

Evaluation results and traces
-----------------------------

``primitive.evaluate(...)`` returns only the encoded output. Calling
``evaluate_with_trace(...)`` returns an evaluation result containing the
output and the concrete value assigned to every input, component output, and
primitive output. That immutable assignment is the *execution trace*.

.. doctest::

   >>> result = AES(number_of_rounds=1).evaluate_with_trace(plaintext, key)
   >>> (result.realization.name, result.execution_engine.name)
   ('lookup', 'python_scalar')
   >>> result.trace.value_of("plaintext")[:4]
   (0, 17, 34, 51)

``result.value_of(source_id)`` is a convenience for looking up the same
component values without going through ``result.trace``.

Transformations and analyses
----------------------------

A *transformation* creates a new graph from an existing one—for example an
inverse, a round-reduced graph, or a slice ending at an intermediate state.
The source graph is never modified. An *analysis* asks a mathematical
question about a graph, possibly using an optional SAT, SMT, MILP, CP, or
computer-algebra backend.

Parameters and validation
-------------------------

Primitive classes validate that supplied parameters are structurally
consistent. They do not imply that arbitrary constants, matrices, or round
counts are cryptographically secure. Parameter catalogues and their
provenance are separate from the generic construction classes.

``PrimeField`` rejects composite moduli. ``BinaryExtensionField`` verifies
that its defining polynomial is irreducible over :math:`GF(2)` and currently
uses the polynomial basis. These checks establish a valid domain; they are not
a certificate that a custom cryptographic design is secure.
