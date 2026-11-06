XOR differential-linear trails: verification
============================================

The differential prefix, connector and linear suffix have different roles.
Their local weights and an actual endpoint experiment must be interpreted
separately. V5 has no general concrete-realizability checker for an arbitrary
composed trail.

Characteristic validation
-------------------------

The fixed Speck32/64 regression fixture has an explicit local-transition check:

.. doctest::

   >>> from claasp.analysis import (
   ...     speck32_xor_differential_linear_legacy_fixture,
   ...     check_speck32_xor_differential_linear_fixture)
   >>> fixture = speck32_xor_differential_linear_legacy_fixture()
   >>> check_speck32_xor_differential_linear_fixture(fixture)
   True

This fixture-specific check recomputes the probability-bearing transitions and
the retained legacy objective. It is not a general graph-wide checker for any
supplied composed trail.

Distinguisher probability/correlation evaluation
------------------------------------------------

Specialised seeded experiments exist for Speck32/64 and ChaCha. For example,
the Speck experiment fixes the key to zero and measures the parity of the
masked output difference over sampled input pairs:

.. doctest::

   >>> from claasp.analysis import run_speck32_xor_differential_linear_experiment
   >>> result = run_speck32_xor_differential_linear_experiment(
   ...     1, 1, rounds=2, samples=64, seed=7)
   >>> result.samples, -1 <= result.correlation <= 1
   (64, True)

This is statistical evidence for the stated primitive, rounds and key setting.
The specialised experiments are not a general primitive-independent checker.
See :doc:`advanced_differential_linear`.
