Getting started
===============

Installation
------------

Install the development package from the ``next`` directory:

.. code-block:: console

   python -m pip install -e .

No SageMath or solver package is required for construction and scalar
evaluation.

Evaluating MiMC
---------------

The following toy MiMC instance operates directly over :math:`GF(17)`:

.. doctest::

   >>> from claasp_next.ciphers import MiMCPermutation
   >>> mimc = MiMCPermutation(
   ...     modulus=17,
   ...     exponent=3,
   ...     round_constants=(1, 2, 4),
   ... )
   >>> mimc.evaluate(5)
   5
   >>> len(mimc.rounds)
   3

The parameters above are deliberately small teaching parameters and must not
be used cryptographically.

Evaluating a batch
------------------

The reference batch evaluator accepts one sequence of samples per cipher
input. It shares scalar semantics and therefore supports arbitrary-size prime
field elements without a machine-word restriction:

.. doctest::

   >>> from claasp_next.evaluators import BatchEvaluator
   >>> batch = BatchEvaluator().evaluate(
   ...     mimc,
   ...     {"state": ((0,), (5,), (16,))},
   ... )
   >>> batch.outputs
   ((7,), (5,), (11,))

This implementation is the correctness reference. Future vectorized or native
evaluators must produce identical results.

Building a typed graph
----------------------

A port contains three logical field elements even though its canonical binary
encoding occupies 15 bits:

.. doctest::

   >>> from claasp_next import Cipher, PrimeField, ValueType
   >>> from claasp_next.components import Permutation
   >>> state_type = ValueType(PrimeField(17), (3,))
   >>> state_type.unit_count
   3
   >>> state_type.encoded_bit_size
   15
   >>> cipher = Cipher("toy", {"state": state_type})
   >>> cipher.add_round().number
   0
   >>> operation = Permutation(cipher.input("state"), (2, 0, 1))
   >>> output = cipher.add_component(operation)
   >>> output.owner_id
   'permutation_0_0'
   >>> cipher.set_output(output)
   >>> cipher.evaluate((3, 5, 8))
   (8, 3, 5)
