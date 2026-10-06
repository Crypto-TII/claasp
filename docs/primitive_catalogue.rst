Primitive catalogue
===================

The public catalogue describes the fixed-length primitives supported by
CLAASP. Classes are available from ``claasp.primitives`` for
ordinary use and from semantic category modules when the distinction matters:

* ``block_ciphers`` and ``tweakable_block_ciphers`` are keyed permutations;
* ``permutations`` are unkeyed permutations;
* ``block_functions`` are keyed fixed-length mappings that need not be
  permutations;
* ``functions`` are unkeyed fixed-length mappings;
* ``single_component_primitives`` and ``toy_primitives`` are explicit
  analysis and teaching fixtures.

The categories describe mathematical interfaces, not execution engines.
Graph realizations remain separate from scalar, batch, and constraint
representations.

Discovering primitives
----------------------

The catalogue returns immutable records before any primitive graph is built.
Queries use committed classification and component metadata; they do not scan
source files or import every implementation module:

.. doctest::

   >>> from claasp.catalogue import catalogue
   >>> aes = catalogue.primitive("AES")
   >>> (aes.category, aes.kind, aes.bijectivity_obligation)
   ('block_ciphers', 'block_cipher', True)
   >>> tuple(item.name for item in aes.inputs)
   ('plaintext', 'key')
   >>> catalogue.primitive("ToyAES").bijectivity_obligation
   True
   >>> [catalogue.primitive(name).bijectivity_obligation for name in ("Identity", "Permutation", "Rotate", "Xor")]
   [True, True, True, True]
   >>> catalogue.primitive("Shift").bijectivity_obligation
   False
   >>> [item.name for item in catalogue.primitives(filters="pure-arx") if item.name in {"ChaCha", "Salsa"}]
   ['ChaCha', 'Salsa']
   >>> all("Xor" in item.components for item in catalogue.primitives(components="xor"))
   True

Category, component, and design filters compose. Design names accept the
familiar ``arx``, ``purearx``, ``andrx``, ``pureandrx``, ``sbox_based``, and
``fsr_based`` spellings, plus hyphenated aliases. A tweakable query is a
mathematical-interface query, not a request for an execution backend.

The obligation is configuration-level retained-input bijectivity. It asks
whether the catalogue's designated data/state input can be recovered while
all auxiliary inputs are retained. It is not a claim that every possible
custom constructor argument is bijective, nor that all inputs of a multi-input
operation can be jointly recovered.

Realizations and parameter sets are records too. Capability queries never
confuse a graph realization with its eventual execution engine:

.. doctest::

   >>> algebraic, = catalogue.realizations(primitive="AES", capabilities="algebraic_semantics")
   >>> algebraic.identity
   'AES:algebraic'
   >>> speck32, = catalogue.parameter_sets(
   ...     primitive="Speck", parameters={"block_bit_size": 32, "key_bit_size": 64})
   >>> dict(speck32.values)
   {'block_bit_size': 32, 'key_bit_size': 64, 'number_of_rounds': 22}

Driver declarations are also safe to inspect in a dependency-free process.
Availability is probed only when explicitly requested, and returns another
record rather than importing the implementation:

.. doctest::

   >>> [item.name for item in catalogue.drivers(kind="execution_engine")]
   ['python_scalar', 'python_batch', 'python_transposed_batch', 'python_generated_source', 'native_generated_c']
   >>> catalogue.driver_availability("python_scalar").available
   True

Representations and analyses form explicit compatibility relationships rather
than being inferred from package names. Queries work in either direction:

.. doctest::

   >>> [item.name for item in catalogue.representations(component="Power")]
   ['concrete_execution', 'primitive_serialization', 'python_generated_source', 'msolve_input', 'prime_field_polynomial', 'primitive_diagram', 'singular_program']
   >>> [item.name for item in catalogue.components(representation="boolean_cnf")]
   ['Add', 'BitVectorSBox', 'BitwiseAnd', 'Constant', 'Identity', 'ModularAdd', 'Permutation', 'Rotate', 'Xor']
   >>> [item.name for item in catalogue.drivers(representation="boolean_cnf")]
   ['minizinc', 'kissat', 'minisat', 'z3', 'glpk']
   >>> "enumerate_xor_differential_trails" in {
   ...     item.name for item in catalogue.analyses(primitive="Speck")}
   True
   >>> "component_property" in {
   ...     item.name for item in catalogue.analyses(primitive="AES")}
   True

These declarations are conservative. For example, AES is not advertised for
the generic Boolean-CNF analysis merely because a CNF module exists: its graph
contains component semantics that the current CNF lowering does not implement.
Records for reduced-round reviewed analyses carry their parameter restriction
explicitly.

Formatting these records as terminal tables, Markdown, CSV, JSON, or dataframes
belongs to the report/presentation layer rather than catalogue semantics.

Single-component primitives mirror the public base-component API exactly.
For example, ``LinearMap`` covers both binary linear layers and finite-field
MixColumn-style matrices, while ``BitVectorSBox`` and ``SBox`` distinguish one
whole-bit-vector lookup from a lookup applied independently to typed units:

.. doctest::

   >>> from claasp import Word
   >>> from claasp.primitives.single_component_primitives import BitVectorSBox, SBox
   >>> BitVectorSBox(2, [3, 2, 1, 0]).evaluate(1)
   2
   >>> SBox([3, 2, 1, 0], Word(2), unit_count=2).evaluate(0b0001)
   14

Primitive kinds and input visibility
------------------------------------

Each graph states its mathematical interface separately from its execution
engine. Inputs also carry a semantic role and a default visibility. Keys are
secret by default, while plaintexts, states, tweaks, and nonces are public:

.. doctest::

   >>> from claasp import InputVisibility, PrimitiveKind
   >>> from claasp.primitives import AES
   >>> aes = AES()
   >>> aes.kind is PrimitiveKind.BLOCK_CIPHER
   True
   >>> aes.secret_inputs
   ('key',)
   >>> aes.input_descriptor("plaintext").visibility is InputVisibility.PUBLIC
   True

Visibility describes a study, not the value or the graph. A known-key study
can therefore derive new metadata without rebuilding or mutating AES:

.. doctest::

   >>> known_key = aes.with_input_visibility(key="public")
   >>> known_key.secret_inputs
   ()
   >>> aes.secret_inputs
   ('key',)

Custom authors may use ``public_input`` and ``secret_input`` when conventional
boundary names are not sufficient. Analyses may override the defaults again
for a particular experiment.

Importing and evaluating a catalogue primitive
----------------------------------------------

Top-level imports are intentionally short. This reduced-round Ascon instance
is still the same 320-bit permutation family:

.. doctest::

   >>> from claasp.primitives import Ascon
   >>> ascon = Ascon(number_of_rounds=4)
   >>> len(ascon.rounds)
   4
   >>> f"{ascon.evaluate(0):080x}"[:16]
   '6e5a585776456145'

The category import resolves to the identical class, which is useful for
catalogue browsers and type-directed applications:

.. doctest::

   >>> from claasp.primitives.permutations import Ascon as CategorizedAscon
   >>> CategorizedAscon is Ascon
   True

Constructor parameters build the graph from readable source. Reduced-round
study variants therefore do not depend on a pre-exported graph file:

.. doctest::

   >>> len(Ascon(number_of_rounds=5).rounds)
   5

The implementation is ordinary Python in
``claasp/primitives/permutations/ascon/primitive.py``. Twofish and WARP likewise
live in ``block_ciphers/twofish.py`` and ``block_ciphers/warp.py``; their round
functions and key schedules can be read directly rather than reconstructed
from serialized component records.

Primitive-owned data
--------------------

Primitives with multiple realizations, parameter sets, generated constants,
or supporting data use a same-import-path package. Poseidon, for example,
owns ``primitive.py``, ``parameters.py``, and its versioned ``data/`` directory.
The convenience namespace remains available:

.. doctest::

   >>> from claasp.parameters import poseidon_bn254_width3
   >>> from claasp.primitives.permutations.poseidon import (
   ...     poseidon_bn254_width3 as owned_poseidon_parameters)
   >>> poseidon_bn254_width3() is owned_poseidon_parameters()
   True

Simple primitives remain single modules. A family package co-locates alternate
realizations without changing the canonical import path. For example,
``permutations.keccak`` contains ``primitive.py``, ``sbox.py``, and
``invertible.py``; ``block_ciphers.tinyjambu`` contains its canonical, word,
and feedback-register realizations. AES uses a package for reusable blocks and
multiple realizations, LowMC for vetted constant files, and Poseidon for its
typed parameter catalogue and licensed data. Simon, Simeck, and Gimli S-box
forms are explicitly labelled alternate realizations, not descriptions of
their canonical specifications. There are no runtime frozen-graph indexes or
compressed graph specifications.
