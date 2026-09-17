Implementing a primitive
=========================

Primitive code should resemble the primitive's pseudocode. Whole ports can be
passed directly to components, indexing selects logical units, and component
identifiers are optional.

``input(name_or_position)`` returns one graph input port. ``inputs()`` returns
all input ports in declaration order, while selectors can request a subset in
an explicit order. These methods expose graph references, not runtime values,
and deliberately leave the collection representation unspecified. The
``input_ports`` mapping is reserved for representations and other consumers
that need names and ports together.

.. doctest::

   >>> from claasp_next import Primitive, PrimeField, ValueType
   >>> from claasp_next.components import Add, Permutation
   >>> field_vector = ValueType(PrimeField(17), (3,))
   >>> primitive = Primitive("small_permutation", {"state": field_vector})
   >>> state = primitive.input("state")
   >>> primitive.input(0) is state
   True
   >>> list(primitive.inputs("state")) == [state]
   True
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
so rebuilding the same graph produces the same names.  Normal primitive source
should omit identifiers and retain semantic ports instead, for example
round states or round keys. Publish precomputed collections through
``set_round_states()`` and ``set_round_keys()``, or record them incrementally
with ``add_round_state()`` and ``add_round_key()``. Named operation landmarks
similarly use ``add_round_operations()``. Primitive source therefore does not
assign a particular container to public attributes. This keeps analysis code
stable when an implementation or the library's collection representation
changes. Explicit identifiers remain available for exceptional interchange
contracts; duplicates are rejected.

``Primitive.select_configuration``, ``validate_number_of_rounds``, and
``validate_positive_integer`` centralize the common parameter checks.  See the
direct ``AES``, ``Speck``, and ``ChaCha`` sources for full reference examples:
their local variables follow the specification pseudocode (``state``;
``x``/``y``; and ``a``/``b``/``c``/``d``), while ``CustomAES`` demonstrates
the reusable-block style. Composite outputs are ordered, so a key schedule can
be read naturally as ``key_schedule.output[round_number]``; named lookup is
also available for self-documenting boundaries.

Use ``primitive.join(left, right)`` when several homogeneous ports form one
state for a later operation, or simply ``primitive.set_output((left, right))``
at the boundary. This is structural wiring. The flat representation may retain
an internal normalization node, but primitive source need not construct or
name a ``Concatenate`` component.

The ``claasp_next.utils`` module provides reusable finite-field arithmetic,
fixed-width integer/word conversion, rotations, sequence shifts, and layout
helpers. Primitive classes should contain their round and key-schedule logic,
not private copies of generic mathematics.

.. doctest::

   >>> from claasp_next.utils import int_to_words, reverse_bytes_in_words
   >>> int_to_words(0x01234567, 8, 32)
   (1, 35, 69, 103)
   >>> reverse_bytes_in_words(range(32))[:8]
   (24, 25, 26, 27, 28, 29, 30, 31)

These helpers validate widths and ordering explicitly and do not import Sage.
The AES implementation is the current full-size example.

Reusable component catalogue
----------------------------

``claasp_next.components`` is the central public catalogue. Components are
immutable graph descriptions; evaluators and solver representations remain
separate execution engines. The single authoring path is
``Primitive.add_component``, which validates graph ownership and assigns a
deterministic identifier when one is omitted.

The catalogue includes structural operations, conversions, lookup
substitution, Boolean logic, word/ARX arithmetic, algebraic and finite-field
maps, feedback registers, and reusable permutation layers. Word operations
make wraparound explicit: rotations wrap, shifts zero-fill, and modular
arithmetic is distinct from ordinary field arithmetic.

.. doctest::

   >>> from claasp_next import Primitive, ValueType, Word
   >>> from claasp_next.components import ModularSubtract, Shift
   >>> words = ValueType(Word(8), (1,))
   >>> arx = Primitive("word_example", {"left": words, "right": words})
   >>> arx.add_round()
   Round(number=0)
   >>> difference = arx.add_component(ModularSubtract((arx.input("left"), arx.input("right"))))
   >>> shifted = arx.add_component(Shift(difference, 1, "right"))
   >>> arx.set_output(shifted)
   >>> arx.evaluate(3, 5)
   127

Feedback is described by typed terms rather than nested unlabelled lists. A
binary-extension-field domain similarly makes word-register multiplication
unambiguous.

.. doctest::

   >>> from claasp_next import Bit
   >>> from claasp_next.components import FeedbackRegister, FeedbackRegisterSpec, FeedbackTerm
   >>> lfsr = Primitive("lfsr", {"state": ValueType(Bit(), (4,))})
   >>> lfsr.add_round()
   Round(number=0)
   >>> spec = FeedbackRegisterSpec(4, (FeedbackTerm((0,)), FeedbackTerm((1,))))
   >>> next_state = lfsr.add_component(FeedbackRegister(lfsr.input("state"), (spec,)))
   >>> lfsr.set_output(next_state)
   >>> lfsr.evaluate(0b1011)
   7

Permutation-specific helpers return ordinary generic components. For example,
``shift_rows`` returns ``Permutation``, while ``sigma`` and the Gaston,
Keccak, and Xoodoo theta helpers return ``LinearMap``. This keeps their graph
semantics reusable by every execution or analysis backend.

Conversions between bits and words are graph operations rather than implicit
evaluator behavior. ``PackBits`` and ``UnpackBits`` use an explicit MSB-first
convention, so the same graph has unambiguous scalar and batch semantics.

.. doctest::

   >>> from claasp_next import Bit, Primitive, ValueType
   >>> from claasp_next.components import PackBits, UnpackBits
   >>> conversion = Primitive("conversion", {"bits": ValueType(Bit(), (16,))})
   >>> conversion.add_round()
   Round(number=0)
   >>> words = conversion.add_component(PackBits(conversion.input("bits"), 8))
   >>> bits = conversion.add_component(UnpackBits(words))
   >>> conversion.set_output(bits)
   >>> conversion.evaluate(0x1234)
   4660

Catalogue categories
--------------------

The public catalogue classifies fixed-length maps by their mathematical
interface.  Unkeyed maps belong to ``permutations`` when bijectivity is an
obligation and to ``functions`` otherwise.  Keyed maps use ``block_ciphers``
or ``block_functions``; an explicit tweak promotes those categories to
``tweakable_block_ciphers`` or ``tweakable_block_functions``.  Execution
engines and graph realizations do not change this classification.

``single_component_primitives`` and ``toy_primitives`` are orthogonal fixture
folders.  Hash, MAC, and stream constructions are not catalogue categories:
only a fixed-length core is catalogued, with the higher-level construction
recorded as provenance.  A catalogue record also states its external input
roles and whether bijectivity must eventually be demonstrated by the migrated
implementation.  Helpers and documentation modules receive an explicit
outside-scope disposition instead of being silently counted as primitives.

Each module under ``single_component_primitives`` contains the public class it
advertises. For example, ``single_component_primitives.and.And`` directly
shows the complete reference sequence: initialize ``Primitive``, call
``add_round()``, construct the operation, call ``add_component()``, and bind it
with ``set_output()``. Shared private code is limited to validation and
finite-field/matrix helpers, so following an import path always reaches the
primitive definition rather than a forwarding shim or hidden graph builder.

Primitive authors supply mathematical parameters using ordinary lists. The
component and utility layers validate shape, orientation, domains, and stable
internal storage. Matrix comprehensions and container freezing therefore do
not belong in primitive definitions.

.. doctest::

   >>> from claasp_next.components import FeedbackRegisterParameters
   >>> from claasp_next.primitives.single_component_primitives import Fsr, LinearLayer, MixColumn
   >>> linear = LinearLayer(2, matrix=[[1, 0], [1, 1]])
   >>> linear.evaluate(0b10)
   3
   >>> mixing = MixColumn(4, [[1, 0], [0, 1]])
   >>> hex(mixing.evaluate(0xAB))
   '0xab'
   >>> feedback = FeedbackRegisterParameters.from_taps(4, [0, 1])
   >>> Fsr(4, parameters=feedback).evaluate(0b1010)
   5

``FeedbackRegisterParameters.from_legacy_description()`` confines the nested
v4 FSR encoding to an explicit compatibility boundary. New code can use
``from_taps()`` or construct typed ``FeedbackRegisterSpec`` and
``FeedbackTerm`` values directly; both accept ordinary iterables and perform
their own normalization.
