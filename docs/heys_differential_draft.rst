G) Differential Cryptanalysis on Heys Toy Cipher
================================================

Objective
---------

Knowing that the input and output sizes are :math:`n` bits,
the goal of differential cryptanalysis is to find an input
difference/output difference pair that occurs with a
probability significantly higher than the probability
expected for a random mapping, approximately

.. math::

   \frac{1}{2^n}

For the Heys cipher, we consider a differential
characteristic covering the first three rounds.

The input plaintext difference is

.. math::

   \Delta P = [0000\ 1011\ 0000\ 0000].

After three rounds, the characteristic leads to the
following difference at the input of the fourth round:

.. math::

   \Delta U_4 = [0000\ 0110\ 0000\ 0110].

The probability of this differential characteristic is

.. math::

   P_D = \frac{8}{16} \times \frac{6}{16}
         \times \left(\frac{6}{16}\right)^2
       = \frac{27}{1024}.

This probability is calculated by multiplying the
probabilities of the active S-box transitions, assuming
their independence.

For example, given the plaintext

.. math::

   P = [1111\ 1111\ 1111\ 1111],

we construct a second plaintext by applying the chosen
input difference:

.. math::

   P' = P \oplus \Delta P
      = [1111\ 0100\ 1111\ 1111].

Encrypting these two plaintexts allows us to study
how their difference propagates through the cipher.

The characteristic predicts that the difference at
the input of the fourth round will be

.. math::

   \Delta U_4 = [0000\ 0110\ 0000\ 0110]

with an estimated probability of :math:`27/1024`.

Note that :math:`\Delta U_4` is an intermediate
difference, not the final ciphertext difference.
This characteristic can be exploited to recover
information about the last-round subkey, as we will
discuss later.


Step 1: Find good differential of an Sbox with its DDT
------------------------------------------------------

Similarly to what we did to find a good linear approximation,
we will first see how to find a good differential from the
S-box.

Let us recall that the inputs of the S-box are represented
as :math:`X = [X_1\ X_2\ X_3\ X_4]` and the outputs as
:math:`Y = [Y_1\ Y_2\ Y_3\ Y_4]`.

All difference pairs of an S-box :math:`(\Delta X, \Delta Y)`
can be analyzed to determine the probability of obtaining
:math:`\Delta Y` given an input difference :math:`\Delta X`.

For the Heys cipher, it works as follows.

For each possible input difference

.. math::

   \Delta X \in \{0,\dots,15\},

we evaluate all possible inputs

.. math::

   X \in \{0,\dots,15\}.

For every input :math:`X`, we compute

.. math::

   X' = X \oplus \Delta X

and then calculate the corresponding output difference

.. math::

   \Delta Y = S(X) \oplus S(X').

Finally, we count how many times the pair
:math:`(\Delta X, \Delta Y)` occurs. Dividing this count
by 16 gives the probability.

For example:

* The pair :math:`\Delta X = (1011)_2` and
  :math:`\Delta Y = (0010)_2` occurs 8 times out of 16
  through the S-box, giving a probability of
  :math:`8/16 = 1/2`.

* The pair :math:`\Delta X = (1000)_2` and
  :math:`\Delta Y = (1011)_2` occurs 4 times out of 16
  through the S-box, giving a probability of
  :math:`4/16 = 1/4`.

We can reproduce these calculations using the Heys S-box
already defined in CLAASP v5:

.. code-block:: python

   from claasp.primitives.toy_primitives.heys import HEYS_SBOX

   def transition_count(delta_x, delta_y):
       return sum(
           (HEYS_SBOX[x] ^ HEYS_SBOX[x ^ delta_x]) == delta_y
           for x in range(16)
       )

   for delta_x, delta_y in [(0xb, 0x2), (0x8, 0xb)]:
       count = transition_count(delta_x, delta_y)
       print(f"{delta_x:#x} -> {delta_y:#x}: {count}/16")

The output is:

.. code-block:: text

   0xb -> 0x2: 8/16
   0x8 -> 0xb: 4/16

A complete enumeration of all differentials of an S-box
is given by its Difference Distribution Table (DDT).

The rows represent :math:`\Delta X` values (in hexadecimal),
and the columns represent :math:`\Delta Y` values
(in hexadecimal). Each element of the table represents
the number of occurrences of the corresponding output
difference, given the input difference.

We can construct the complete DDT as follows:

.. code-block:: python

   ddt = [
       [
           transition_count(delta_x, delta_y)
           for delta_y in range(16)
       ]
       for delta_x in range(16)
   ]

   print("    " + " ".join(f"{i:2x}" for i in range(16)))
   for delta_x, row in enumerate(ddt):
       print(f"{delta_x:2x}: " +
             " ".join(f"{count:2d}" for count in row))


The resulting Difference Distribution Table is:

.. csv-table:: Heys S-box Difference Distribution Table
   :header: "ΔX/ΔY", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"

   "0", 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
   "1", 0, 0, 0, 2, 0, 0, 0, 2, 0, 2, 4, 0, 4, 2, 0, 0
   "2", 0, 0, 0, 2, 0, 6, 2, 2, 0, 2, 0, 0, 0, 0, 2, 0
   "3", 0, 0, 2, 0, 2, 0, 0, 0, 0, 4, 2, 0, 2, 0, 0, 4
   "4", 0, 0, 0, 2, 0, 0, 6, 0, 0, 2, 0, 4, 2, 0, 0, 0
   "5", 0, 4, 0, 0, 0, 2, 2, 0, 0, 0, 4, 0, 2, 0, 0, 2
   "6", 0, 0, 0, 4, 0, 4, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2
   "7", 0, 0, 2, 2, 2, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 4
   "8", 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 4, 0, 4, 2, 2
   "9", 0, 2, 0, 0, 2, 0, 0, 4, 2, 0, 2, 2, 2, 0, 0, 0
   "a", 0, 2, 2, 0, 0, 0, 0, 0, 6, 0, 0, 2, 0, 0, 4, 0
   "b", 0, 0, 8, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 2, 0, 2
   "c", 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 0, 2, 0, 6, 0, 0
   "d", 0, 4, 0, 0, 0, 0, 0, 4, 2, 0, 2, 0, 2, 0, 2, 0
   "e", 0, 0, 2, 4, 2, 0, 0, 0, 6, 0, 0, 0, 0, 0, 2, 0
   "f", 0, 2, 0, 0, 6, 0, 0, 0, 0, 4, 0, 2, 0, 0, 2, 0

The resulting DDT contains 16 rows and 16 columns,
corresponding to all possible input and output differences.

Each entry gives the number of input values producing
the corresponding output difference.

For example, the entry in row ``b`` and column ``2``
is 8, corresponding to a differential probability of
:math:`8/16 = 1/2`.

Similarly, the entry in row ``8`` and column ``b``
is 4, corresponding to a probability of
:math:`4/16 = 1/4`.

The sum of each row is 16, since every possible input
value contributes to exactly one output difference.

Step 2: Constructing a differential for the Complete Cipher
-----------------------------------------------------------

Step 3: Exploiting the above differential trail
-----------------------------------------------


H) Finding differential trails with CLAASP on Heys toy cipher
==============================================================

1) Find an optimal differential trail using CP
----------------------------------------------

2) Find one differential trail (not an optimal one)
---------------------------------------------------

3) Find all differential trail of chosen weight
-----------------------------------------------

4) Find a differential trail of a given weight
----------------------------------------------

5) Find a differential trail starting from a fixed difference
-------------------------------------------------------------


I) Finding differential trails with CLAASP on real cipher
=========================================================


J) Summary of Differential Cryptanalysis
========================================