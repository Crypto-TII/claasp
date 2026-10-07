Getting started
===============

Installation
------------

Install the package from the repository root:

.. code-block:: console

   python -m pip install -e .

The evaluation and avalanche examples need no external program. The
differential-trail example uses Kissat. On macOS or Linux with Homebrew,
install it with ``brew install kissat``. Other systems can build Kissat from
its official source distribution.

Evaluate AES
------------

Create AES, supply a plaintext and key, and evaluate a standard test vector:

.. doctest::

   >>> from claasp.primitives import AES
   >>> aes = AES()
   >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
   >>> key = 0x000102030405060708090A0B0C0D0E0F
   >>> ciphertext = aes.evaluate(plaintext=plaintext, key=key)
   >>> f"{ciphertext:032x}"
   '69c4e0d86a7b0430d8cdb78070b4c55a'

AES accepts a 128-bit ``plaintext`` and a 128-bit ``key`` and returns the
128-bit ciphertext. Other traditional block ciphers use the same packed
integer convention.

Find a differential trail
-------------------------

A differential trail follows an XOR difference through each round of a
primitive. CLAASP can search for the lowest-weight—and therefore most
probable—trail. CLAASP uses Kissat by default for this search:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> speck = Speck(number_of_rounds=2)
   >>> trail = speck.analysis.find_lowest_weight_xor_differential_trail()

Display the result:

.. code-block:: python

   trail.show()

A representative run produces the following report. Solver runtime and peak
memory depend on the machine:

.. code-block:: text

   Trail

   Trail summary

   Field          |                                                                Value
   ---------------+---------------------------------------------------------------------
   kind           |                                                     xor_differential
   input          |                                                           0x00408000
   output         |                                                           0x0002000a
   total weight   |                                                                    1
   lower bound    |                                                                    1
   optimality     |                                                       proved optimal
   search method  | SAT optimization by binary search over the differential-weight bound
   solver         |                                                               Kissat
   solver version |                                                                4.0.4
   runtime        |                                                     0.203444 seconds
   peak memory    |                                                        4337664 bytes

   Component transitions

   Round | Component        | Input      | Output | Exact ratio | Sign | Weight | Component ID
   ------+------------------+------------+--------+-------------+------+--------+----------------
       0 | rotate right 7   | 0x0040     | 0x8000 |         1/1 |    1 |      0 | rotate_0_0
       0 | modular addition | 0x80008000 | 0x0000 |         1/1 |    1 |      0 | modular_add_0_1
       0 | XOR              | 0x00000000 | 0x0000 |         1/1 |    1 |      0 | xor_0_2
       0 | rotate left 2    | 0x8000     | 0x0002 |         1/1 |    1 |      0 | rotate_0_3
       0 | XOR              | 0x00020000 | 0x0002 |         1/1 |    1 |      0 | xor_0_4
       1 | rotate right 7   | 0x0000     | 0x0000 |         1/1 |    1 |      0 | rotate_1_0
       1 | modular addition | 0x00000002 | 0x0002 |         1/2 |    1 |      1 | modular_add_1_1
       1 | XOR              | 0x00020000 | 0x0002 |         1/1 |    1 |      0 | xor_1_2
       1 | rotate left 2    | 0x0002     | 0x0008 |         1/1 |    1 |      0 | rotate_1_3
       1 | XOR              | 0x00080002 | 0x000a |         1/1 |    1 |      0 | xor_1_4

The displayed report contains the input and output differences, total weight,
proof bound, search metadata, and every data-state transition. Here the
weight is 1, corresponding to trail probability :math:`2^{-1}` in the
differential model. The matching lower bound confirms that no lower-weight
trail exists for this instance. This is a single-key search, so the all-zero
key-schedule propagation is omitted.

CLAASP first asks Kissat for a feasible trail, then uses binary search over
the maximum weight. An unsatisfiable bound immediately below weight 1 proves
that the displayed trail is optimal. Another SAT solver may return a different
trail with the same optimal weight.

Measure avalanche behavior
--------------------------

An avalanche experiment changes one plaintext bit at a time and measures how
many output bits change. Fixing the key and seed makes the experiment
reproducible:

.. doctest::

   >>> avalanche = speck.analysis.avalanche(
   ...     "plaintext", 8, seed=9, fixed_inputs={"key": 0}
   ... )
   >>> avalanche.input_bit_count, avalanche.output_bit_count
   (32, 32)
   >>> round(sum(avalanche.mean_changed_output_bits) / 32, 2)
   9.47

Eight samples keep this introductory example quick. Use more samples before
drawing conclusions about a primitive; an avalanche result is experimental
evidence, not a proof.

More quick analyses
-------------------

See :doc:`quick_analysis_scripts` for short examples that find a linear trail,
generate data for a neural distinguisher, inspect AES round values, and repeat
the analyses above with explanations of their results.
