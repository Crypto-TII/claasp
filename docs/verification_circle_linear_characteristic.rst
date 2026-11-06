Circle-linear characteristic validation
=======================================

``CircleLinearTrailModel`` currently uses the ``perfect_subgroup_spn`` backend.
It validates the required S-box subgroup and diffusion structure when the
model is built. ``trail(output_code)`` reconstructs the canonical compatible
mask sequence, derives each round contribution and intersects its affine key
conditions. This is restricted canonical-trail reconstruction; it is not a
general independent ``check_characteristic()`` API for arbitrary circle trails.

.. doctest::

   >>> from claasp.primitives import Craft
   >>> model = Craft(number_of_rounds=8).circle_linear_trail_model()
   >>> result = model.search()
   >>> trail = result.representative
   >>> model.trail(trail.output_code) == trail
   True
   >>> model.backend, result.scope
   ('perfect_subgroup_spn', 'four-element perfect subgroup')
   >>> trail.conditions.contains(0)
   True
   >>> abs(trail.contribution(0))
   Fraction(1, 256)

The retained round contributions can be multiplied for a concrete key,
including their signs and zero contributions outside their local key classes:

.. doctest::

   >>> from fractions import Fraction
   >>> product = Fraction(1)
   >>> for step in trail.round_transitions:
   ...     product *= step.sbox_sign * step.affine.coefficient(0)
   >>> product == trail.contribution(0)
   True

These operations validate or reconstruct the selected subgroup characteristic.
They do not prove a lower bound on the actual endpoint correlation. See
:doc:`basic_circle_linear_correlations` for exact and sampled endpoint evaluation.
