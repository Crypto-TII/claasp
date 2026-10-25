Implementing a primitive
=========================

For a complete worked implementation, continue to
:doc:`implementing_toy_spn` after this reference to the authoring operations.

Primitive code should resemble the primitive's pseudocode. Whole unit arrays can be
passed directly to components, indexing selects logical units, and component
identifiers are optional.

``input(name_or_position)`` returns one graph input array. ``inputs()`` returns
all input arrays in declaration order, while selectors can request a subset in
an explicit order. These methods expose graph references, not runtime values,
and deliberately leave the collection representation unspecified. The
``input_arrays`` mapping is reserved for representations and other consumers
that need names and arrays together.

.. doctest::

   >>> from claasp import PrimitiveBuilder, UnitArrayType
   >>> from claasp.components import Add, Permutation
   >>> from claasp.unit_types import PrimeField
   >>> field_vector = UnitArrayType(PrimeField(17), (3,))
   >>> builder = PrimitiveBuilder("small_permutation", {"state": field_vector})
   >>> state = builder.input("state")
   >>> builder.input(0) is state
   True
   >>> list(builder.inputs("state")) == [state]
   True
   >>> state[2, 0].positions
   (2, 0)
   >>> builder.add_round()
   Round(number=0)
   >>> shuffled = builder.add_component(Permutation(state, (2, 0, 1)))
   >>> shuffled.source_id
   'permutation_0_0'
   >>> output = builder.add_component(Add(shuffled, state))
   >>> output.source_id
   'add_0_1'
   >>> primitive = builder.build(output)

``Add(a, b)``, ``ModularAdd(a, b)``, and ``Xor(a, b)`` accept operands as
separate arguments. They also accept one iterable, such as ``Add(builder.inputs())``.
Supply an explicit identifier with ``component_id="name"`` when needed.

Automatic identifiers combine the component kind, round number, and position,
so rebuilding the same graph produces the same names.  Normal primitive source
should omit identifiers and retain the returned unit arrays instead. Mark a value for
inspection with ``builder.set_intermediate_output(value, name=...)`` and mark
the current round boundary with ``builder.set_round_output(value)``. The latter
is shorthand for an intermediate output named ``round_output``. Round keys use
``builder.set_round_keys()`` or incremental ``builder.add_round_key()`` calls.
Primitive source therefore does not
assign a particular container to public attributes. This keeps analysis code
stable when an implementation or the library's collection representation
changes. Explicit identifiers remain available for exceptional interchange
contracts; duplicates are rejected.

``Primitive.select_configuration``, ``validate_number_of_rounds``, and
``validate_positive_integer`` centralize the common parameter checks.  See the
direct ``AES``, ``Speck``, and ``ChaChaPermutation`` sources for full reference examples:
their local variables follow the specification pseudocode (``state``;
``x``/``y``; and ``a``/``b``/``c``/``d``), while ``CustomAES`` demonstrates
the reusable-block style. Composite outputs are ordered, so a key schedule can
be read naturally as ``key_schedule.output[round_number]``; named lookup is
also available for self-documenting boundaries.

Use ``builder.join(left, right)`` when several homogeneous unit arrays form one
state for a later operation, or simply ``builder.build((left, right))``
at the boundary. This creates an addressable typed binding, not a semantic
component, so component queries contain only actual operations.

The ``claasp.utils`` module provides reusable finite-field arithmetic,
fixed-width integer/word conversion, rotations, sequence shifts, and layout
helpers. Primitive classes should contain their round and key-schedule logic,
not private copies of generic mathematics.

.. doctest::

   >>> from claasp.utils import int_to_words, reverse_bytes_in_words
   >>> int_to_words(0x01234567, 8, 32)
   (1, 35, 69, 103)
   >>> reverse_bytes_in_words(range(32))[:8]
   (24, 25, 26, 27, 28, 29, 30, 31)

These helpers validate widths and ordering explicitly and do not import Sage.
The AES implementation is the current full-size example.

Reusable component catalogue
----------------------------

``claasp.components`` is the central public catalogue. Components are
immutable graph descriptions; evaluators and solver representations remain
separate execution engines. The single authoring path is
``PrimitiveBuilder.add_component``, which validates graph ownership and assigns a
deterministic identifier when one is omitted.

The catalogue includes structural operations, conversions, lookup
substitution, Boolean logic, word/ARX arithmetic, algebraic and finite-field
maps, feedback registers, and reusable permutation layers. Word operations
make wraparound explicit: rotations wrap, shifts zero-fill, and modular
arithmetic is distinct from ordinary field arithmetic.

.. doctest::

   >>> from claasp import PrimitiveBuilder, UnitArrayType
   >>> from claasp.components import ModularSubtract, Shift
   >>> from claasp.unit_types import Word
   >>> words = UnitArrayType(Word(8), (1,))
   >>> builder = PrimitiveBuilder("word_example", {"left": words, "right": words})
   >>> builder.add_round()
   Round(number=0)
   >>> difference = builder.add_component(
   ...     ModularSubtract((builder.input("left"), builder.input("right"))))
   >>> shifted = builder.add_component(Shift(difference, 1, "right"))
   >>> arx = builder.build(shifted)
   >>> arx.evaluate(3, 5)
   127

Feedback is described by typed terms rather than nested unlabelled lists. A
binary-extension-field unit type similarly makes word-register multiplication
unambiguous.

.. doctest::

   >>> from claasp.unit_types import Bit
   >>> from claasp.components import FeedbackRegister, FeedbackRegisterSpec, FeedbackTerm
   >>> builder = PrimitiveBuilder("lfsr", {"state": UnitArrayType(Bit(), (4,))})
   >>> builder.add_round()
   Round(number=0)
   >>> spec = FeedbackRegisterSpec(4, (FeedbackTerm((0,)), FeedbackTerm((1,))))
   >>> next_state = builder.add_component(FeedbackRegister(builder.input("state"), (spec,)))
   >>> lfsr = builder.build(next_state)
   >>> lfsr.evaluate(0b1011)
   7

Permutation-specific helpers return ordinary generic components. For example,
``shift_rows`` returns ``Permutation``, while ``sigma`` and the Gaston,
Keccak, and Xoodoo theta helpers return ``LinearMap``. This keeps their graph
semantics reusable by every execution or analysis backend.

Conversions between bits and words are typed graph bindings rather than
implicit evaluator behavior or cryptographic operations. ``pack_bits`` and
``unpack_bits`` use an explicit MSB-first convention, so the same graph has
unambiguous scalar, batch, diagram, and model semantics.

.. doctest::

   >>> from claasp import PrimitiveBuilder, UnitArrayType
   >>> from claasp.unit_types import Bit
   >>> builder = PrimitiveBuilder("conversion", {"bits": UnitArrayType(Bit(), (16,))})
   >>> builder.add_round()
   Round(number=0)
   >>> words = builder.pack_bits(builder.input("bits"), 8)
   >>> bits = builder.unpack_bits(words)
   >>> conversion = builder.build(bits)
   >>> conversion.evaluate(0x1234)
   4660

Single-component primitive modules
----------------------------------

Each module under ``single_component_primitives`` contains the public class it
advertises. For example, ``single_component_primitives.bitwise_and.BitwiseAnd`` directly
shows the complete reference sequence: initialize ``PrimitiveBuilder``, call
``add_round()``, construct the operation, call ``add_component()``, and finish
with ``build()``. Shared private code is limited to validation and
finite-field/matrix helpers, so following an import path always reaches the
primitive definition rather than a forwarding shim or hidden graph builder.

Primitive authors supply mathematical parameters using ordinary lists. The
component and utility layers validate shape, orientation, unit types, and stable
internal storage. Matrix comprehensions and container freezing therefore do
not belong in primitive definitions.

.. doctest::

   >>> from claasp.unit_types import BinaryExtensionField
   >>> from claasp.components import FeedbackRegisterParameters
   >>> from claasp.primitives.single_component_primitives import FeedbackRegister, LinearMap
   >>> linear = LinearMap([[1, 0], [1, 1]])
   >>> linear.evaluate(0b10)
   3
   >>> field = BinaryExtensionField(4, 0b10011)
   >>> mixing = LinearMap([[1, 0], [0, 1]], field)
   >>> hex(mixing.evaluate(0xAB))
   '0xab'
   >>> feedback = FeedbackRegisterParameters.from_taps(4, [0, 1])
   >>> FeedbackRegister(feedback).evaluate(0b1010)
   5

``LinearMap`` accepts one row-major matrix and infers the input size from its
columns. Its unit type distinguishes an ordinary binary linear layer from a
MixColumn-style finite-field matrix; these are not separate operations.
``FeedbackRegister`` accepts typed feedback parameters. Use ``from_taps()`` for a
simple Fibonacci register, or construct ``FeedbackRegisterSpec`` and
``FeedbackTerm`` values for multiple, nonlinear, or clocked registers.

The folder is a one-to-one view of the public base-component classes, including
``Add``, ``Multiply``, ``Power``, and ``BinaryAffineMap``.
Structural joins and bit/word views are deliberately absent. Every wrapper has exactly one round and one
component, and its class docstring contains a runnable minimal example.
Component class names use consistent Python capitalization, such as
``ModularAdd``, ``SBox``, and ``FeedbackRegister``.

Lookup tables are immutable validated values rather than loose lists once they
enter the component layer. ``LookupTable`` owns input/output widths, entry
validation, identity construction, and the bijectivity question used to
classify a primitive:

.. doctest::

   >>> from claasp.components import LookupTable
   >>> table = LookupTable([3, 2, 1, 0], input_bit_size=2)
   >>> table.is_bijective()
   True
   >>> compression = LookupTable([0, 0, 1, 1], input_bit_size=2, output_bit_size=1)
   >>> compression.is_bijective()
   False

``BitVectorSBox`` and ``SBox`` still accept ordinary lists for concise primitive
source; each immediately converts that list to a ``LookupTable`` before
choosing its kind or constructing the component.

Other one-component primitives follow the same rule: pass the mathematical
parameter directly. A permutation uses ``output[i] = input[mapping[i]]`` and
rotation direction is an explicit word.

.. doctest::

   >>> from claasp.primitives.single_component_primitives import Permutation, Rotate
   >>> hex(Permutation([1, 0], 4).evaluate(0xAB))
   '0xba'
   >>> hex(Rotate(8, 2, "left").evaluate(0x81))
   '0x6'
