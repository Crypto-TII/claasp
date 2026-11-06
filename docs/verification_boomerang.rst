Boomerang analysis: verification
================================

V5 provides a specialised Speck32/64 endpoint experiment. It does not expose a
general boomerang characteristic validator or concrete-trail realizability
checker through this guide.

Distinguisher probability/correlation evaluation
------------------------------------------------

``run_speck32_boomerang_experiment()`` measures the boomerang return rate using
encryption and decryption. It draws a fresh key and plaintext for each sample,
so its result describes that key-averaged experiment, not an arbitrary fixed
key or the product of one selected pair of differential trail probabilities.

.. doctest::

   >>> from claasp.analysis import run_speck32_boomerang_experiment
   >>> result = run_speck32_boomerang_experiment(1, 1, rounds=2, samples=64, seed=7)
   >>> result.samples, 0 <= result.rate <= 1
   (64, True)

The observed rate is empirical rather than an exact probability. See
:doc:`advanced_boomerang` for the search context and
:doc:`trail_search_introduction` for the distinction between a characteristic
and an endpoint experiment.
