Core concepts
=============

Domains and encodings
---------------------

A domain defines the mathematical meaning of a scalar. A Python integer is
only its runtime representation. For example, ``0x57`` can represent an
unsigned byte, a bit vector, or an element of :math:`GF(2^8)`; those values do
not have the same multiplication operation.

.. doctest::

   >>> from claasp_next import BinaryExtensionField, PrimeField, Word
   >>> aes_field = BinaryExtensionField(8, 0x11B)
   >>> aes_field.encoded_bit_size
   8
   >>> PrimeField(257).contains(256)
   True
   >>> PrimeField(257).contains(257)
   False
   >>> Word(8).contains(0x57)
   True

``Word(8)`` and ``BinaryExtensionField(8, 0x11B)`` share an encoding size but
not algebra: the former supports modular integer addition and rotation, while
the latter supports polynomial-basis field arithmetic.

Logical-unit selections
-----------------------

Graph connections address domain elements rather than implicit bits. A
selection preserves its source domain and obtains a new one-dimensional
shape.

.. doctest::

   >>> from claasp_next import Port, ValueType
   >>> state = Port("state", ValueType(PrimeField(257), (4,)))
   >>> selected = state[3, 1]
   >>> selected.positions
   (3, 1)
   >>> selected.value_type.unit_count
   2

Components and backends
-----------------------

Components are immutable operation descriptions. They do not contain methods
for every evaluator or solver. An evaluator or analysis backend explicitly
registers the component types it supports. Unsupported operations fail rather
than being silently decomposed into bits.

Parameter responsibility
------------------------

Primitive classes validate the structural consistency of supplied parameters.
They do not imply that arbitrary constants, matrices, or round counts are
cryptographically secure. Verified parameter catalogues and their provenance
are separate from the generic construction classes.

Field-definition validation
---------------------------

``PrimeField`` rejects composite moduli. The dependency-free test is
deterministic below :math:`2^{64}` and uses strong Miller--Rabin probable-prime
screening for larger values. Cryptographic parameter provenance is still
required: probabilistic screening is not a primality certificate.

``BinaryExtensionField`` verifies that its defining polynomial is irreducible
over :math:`GF(2)` and currently supports the polynomial basis explicitly.
