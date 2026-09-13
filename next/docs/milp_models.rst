MILP models
===========

CLAASP's linear-model core is independent of SageMath and Python solver
packages. Variables, affine expressions, constraints, domains, and objectives
are explicit immutable values:

.. doctest::

   >>> from claasp_next.milp import *
   >>> variables = tuple(LinearVariable(name, VariableKind.BINARY) for name in ("x", "y"))
   >>> model = MILPModel(
   ...     variables,
   ...     (LinearConstraint(LinearExpression.from_terms({"x": 2, "y": 3}), ConstraintSense.LESS_EQUAL, 3, "capacity"),),
   ...     LinearExpression.from_terms({"x": 3, "y": 4}),
   ...     ObjectiveSense.MAXIMIZE,
   ... )
   >>> model.is_feasible({"x": 0, "y": 1})
   True
   >>> model.objective_value({"x": 0, "y": 1})
   4.0

The deterministic CPLEX-LP exporter is suitable for multiple external
optimizers:

.. doctest::

   >>> text = LPExporter().export(model)
   >>> text.startswith("Maximize\n objective: 3 x + 4 y")
   True

The first optional adapter invokes the open-source ``glpsol`` command:

.. code-block:: python

   from claasp_next.milp.solvers import GLPKSolver, MILPStatus

   result = GLPKSolver().solve(model)
   assert result.status is MILPStatus.OPTIMAL
   assert result.objective_value == 4

Every returned assignment is checked against the portable model and its
objective is recomputed. Cipher trail lowering is layered on top of this
representation in the next M10.5 checkpoint.

Weighted PRESENT trails
-----------------------

The first cipher lowering composes every feasible DDT transition of all 32
S-box instances in two-round PRESENT. It connects both layers through the
graph's permutation, requires a nonzero input difference, and minimizes the
sum of exact transition weights:

.. doctest::

   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> from claasp_next.milp import PresentDifferentialMILPModel
   >>> lowering = PresentDifferentialMILPModel(PresentBlockCipher(number_of_rounds=2))
   >>> trail_model = lowering.milp_model()
   >>> len(trail_model.constraints)
   289

The dedicated GLPK integration obtains the established optimum weight 4,
decodes all 32 transitions, and checks every DDT entry and permutation
boundary independently of the linear constraints.
