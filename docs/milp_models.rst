MILP models
===========

CLAASP's linear-model core is independent of SageMath and Python solver
packages. Variables, affine expressions, constraints, domains, and objectives
are explicit immutable values:

.. doctest::

   >>> from claasp.representations.constraints.milp import *
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

   from claasp.drivers.solvers import GLPKSolver, MILPStatus

   result = GLPKSolver().solve(model)
   assert result.status is MILPStatus.OPTIMAL
   assert result.objective_value == 4

Every returned assignment is checked against the portable model and its
objective is recomputed. Primitive trail lowering is layered on top of this
representation in the next M10.5 checkpoint.

Weighted PRESENT trails
-----------------------

The first primitive lowering composes every feasible DDT transition of all 32
S-box instances in two-round PRESENT. It connects both layers through the
graph's permutation, requires a nonzero input difference, and minimizes the
sum of exact transition weights:

.. doctest::

   >>> from claasp.primitives import Present
   >>> from claasp.representations.constraints.milp import PresentDifferentialMILPModel
   >>> lowering = PresentDifferentialMILPModel(Present(number_of_rounds=2))
   >>> trail_model = lowering.milp_model()
   >>> len(trail_model.constraints)
   289

The dedicated GLPK integration obtains the established optimum weight 4,
decodes all 32 transitions, and checks every DDT entry and permutation
boundary independently of the linear constraints.

The compiler also accepts the same shared ``PropagationProblem`` used by SMT:

.. doctest::

   >>> from claasp.semantics import XOR_DIFFERENTIAL
   >>> from claasp.semantics.cryptanalysis import PropagationProblem
   >>> shared = PropagationProblem(Present(number_of_rounds=2), XOR_DIFFERENTIAL)
   >>> PresentDifferentialMILPModel(shared).problem is shared
   True

Consequently a global or per-component semantic override is selected before
the MILP representation is chosen.

Exact graph execution
---------------------

``BooleanGraphMILPModel`` translates complete Boolean execution clauses to
binary inequalities. Negative literals are represented as ``1-x``, positive
literals as ``x``, and every clause requires their sum to be at least one.
This exactly represents nonlinear Boolean operations; it does not drop
modular additions as the legacy partial execution builder did.

.. doctest::

   >>> from claasp.primitives import Speck
   >>> from claasp.representations.constraints.milp import BooleanGraphMILPModel
   >>> from claasp.representations.execution import ScalarEvaluator
   >>> primitive = Speck(number_of_rounds=1)
   >>> execution = BooleanGraphMILPModel(primitive)
   >>> values = ScalarEvaluator().evaluate(primitive, {
   ...     "plaintext": (0x6574, 0x694c), "key": (0x1918, 0x1110, 0x0908, 0x0100)})
   >>> execution.milp_model().is_feasible(execution.witness(values))
   True

``GLPKSolver`` also accepts CNF at the shared analysis facade, so
``primitive.analysis.recover_input(..., solver=GLPKSolver())`` needs no
solver-specific model assembly. The dedicated integration test reproduces
the full Speck-22 legacy output ``A86842F2``. Solver undefined outcomes are
``MILPStatus.UNKNOWN``, never an infeasibility proof; Boolean projection
rejects them explicitly. Solver registries and Sage backend aliases are not
v5 API contracts. Other optimizers remain optional third-party drivers.

Finite component relations
--------------------------

Exact finite relations provide the dependency-free baseline alongside recovered
convex-hull strategies. They do not require Sage, Espresso, or global pickled
inequality caches at runtime.
``FiniteBinaryRelationMILPModel`` selects one supported row and equates every
semantic column to that row. Row selectors are auxiliary variables: this
is not a minimum-facet or minimum-inequality claim.

.. doctest::

   >>> from claasp.representations.constraints.milp import SBoxTransitionMILPModel
   >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
   >>> from claasp.semantics.cryptanalysis import TrailKind, SBoxTransitionSemantics, TruncatedXorDifference
   >>> relation = SBoxTransitionMILPModel(PRESENT_SBOX, TrailKind.XOR_LINEAR)
   >>> fixed = relation.milp_model(input_pattern=1, output_pattern=5)
   >>> transition = relation.decode_transition(relation.relation.witness((0, 0, 0, 1, 0, 1, 0, 1)))
   >>> (transition.weight, transition.sign)
   (1.0, -1)
   >>> semantics = SBoxTransitionSemantics(PRESENT_SBOX)
   >>> str(semantics.truncated_xor_differential(TruncatedXorDifference.parse("0001")))
   '???1'

The complete DDT is computed by derivative counting; the signed full Walsh
table uses an integer fast Walsh transform and is checked against independent
transition counts. These support eight-bit tables without confusing full
Walsh coefficients with half-Walsh legacy LAT entries or discarding nonzero
probability-one transitions. MILP logarithmic objective coefficients are
floating approximations; decoding retains exact counts and signs and checks
the objective against them.

Small-S-box inequality strategies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The legacy full convex hull, greedy facet reduction, and minimum-cardinality
facet cover are available as explicitly named alternatives for four-bit
S-boxes. The portable one-hot ``SBoxTransitionMILPModel`` remains the default.
For example, load the generated PRESENT differential inequalities and select
the minimum-cardinality formulation explicitly:

.. doctest::

   >>> from claasp.representations.constraints.milp import (
   ...     SBoxMILPInequalityStrategy,
   ...     SBoxXorDifferentialMinimumMILPModel,
   ...     load_bundled_sbox_milp_inequalities,
   ... )
   >>> system = load_bundled_sbox_milp_inequalities(
   ...     "present", TrailKind.XOR_DIFFERENTIAL,
   ...     SBoxMILPInequalityStrategy.MINIMUM,
   ... )
   >>> relation = SBoxXorDifferentialMinimumMILPModel(system)
   >>> model = relation.milp_model(input_pattern=1, output_pattern=3)
   >>> transition = relation.decode_transition(relation.witness(1, 3))
   >>> (transition.numerator, transition.denominator, transition.weight)
   (4, 16, 2.0)
   >>> (len(model.variables), relation.inequality_count)
   (11, 25)

The committed JSON bundle was generated from legacy CLAASP commit
``3aacc275`` with ``tools/generate_sbox_milp_inequalities.py`` under Sage 9.5.
Sage and GLPK are generation-time tools only; importing and solving the
resulting v5 models remains Sage-free. Regenerate the data with a Sage Python
environment and verify that the resulting file is unchanged::

   PYTHONPATH=src sage -python tools/generate_sbox_milp_inequalities.py \
       --name present --table 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 \
       --output src/claasp/representations/constraints/milp/data/present_sbox_milp_inequalities.json

The reproducible GLPK benchmark in
``architecture/audits/data/sbox_milp_strategy_benchmark.json`` used ten runs
of one optimized PRESENT S-box transition in the canonical x86_64 Docker
image. Times below are medians in milliseconds; memory is the maximum reported
by GLPK. This deliberately small workload establishes a controlled comparison,
not a universal winner.

.. list-table::
   :header-rows: 1

   * - Semantics
     - Strategy
     - Variables
     - Constraints
     - Build ms
     - Solve ms
     - KiB
   * - Differential
     - one-hot
     - 105
     - 13
     - 0.686
     - 23.422
     - 110.1
   * - Differential
     - full hull
     - 11
     - 512
     - 22.773
     - 24.966
     - 566.3
   * - Differential
     - greedy
     - 11
     - 44
     - 4.707
     - 25.646
     - 87.9
   * - Differential
     - minimum
     - 11
     - 39
     - 4.572
     - 23.912
     - 83.2
   * - Linear
     - one-hot
     - 141
     - 13
     - 0.890
     - 22.749
     - 141.5
   * - Linear
     - full hull
     - 13
     - 1,071
     - 45.376
     - 29.295
     - 1,201
   * - Linear
     - greedy
     - 13
     - 61
     - 5.494
     - 24.434
     - 111.4
   * - Linear
     - minimum
     - 13
     - 53
     - 6.281
     - 25.229
     - 91.2

The reduced formulations use far fewer variables than one-hot and far fewer
constraints than the full hull, while solver times are close on this tiny
case. Complete trail searches require separate benchmarks before any
default-selection decision.

Large-S-box Espresso strategy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Eight-bit S-boxes can explicitly select the recovered Espresso
product-of-sums formulation. The committed AES bundle is validated against all
65,536 input/output pairs when first loaded, then cached as immutable data.
Espresso is needed only to regenerate the bundle:

.. doctest::

   >>> from claasp.representations.constraints.milp import SBoxXorDifferentialEspressoMILPModel
   >>> aes_system = load_bundled_sbox_milp_inequalities(
   ...     "aes", TrailKind.XOR_DIFFERENTIAL,
   ...     SBoxMILPInequalityStrategy.ESPRESSO,
   ... )
   >>> aes_relation = SBoxXorDifferentialEspressoMILPModel(aes_system)
   >>> aes_model = aes_relation.milp_model(input_pattern=1, output_pattern=31)
   >>> aes_transition = aes_relation.decode_transition(aes_relation.witness(1, 31))
   >>> (aes_transition.numerator, aes_transition.denominator, aes_transition.weight)
   (4, 256, 6.0)
   >>> (len(aes_model.variables), aes_relation.inequality_count)
   (19, 8661)

The legacy ``-okiss`` parser expected header lines not emitted by the Espresso
2.3 executable in the CLAASP Docker image. The recovery therefore parses
standard ``espresso -epos`` output and rejects empty output instead of copying
the silent empty-constraint behavior. The generated clauses are independently
checked as bit-set relations before a model is exposed.

Regenerate the committed AES data with::

   PYTHONPATH=src python tools/generate_large_sbox_milp_inequalities.py \
       --name aes --builtin aes \
       --output src/claasp/representations/constraints/milp/data/aes_sbox_milp_inequalities.json

The five-run canonical-Docker benchmark is recorded in
``architecture/audits/data/aes_sbox_milp_strategy_benchmark.json``. Construction
medians below use the immutable bundle cache; ``Cold ms`` includes the first
exhaustive bundle validation. Memory is the maximum reported by GLPK.

.. list-table::
   :header-rows: 1

   * - Semantics
     - Strategy
     - Variables
     - Constraints
     - Cold ms
     - Build ms
     - Solve ms
     - MiB
   * - Differential
     - one-hot
     - 32,402
     - 25
     - 223.5
     - 226.4
     - 316.7
     - 40.8
   * - Differential
     - Espresso
     - 19
     - 8,687
     - 1,739.1
     - 82.2
     - 94.2
     - 15.6
   * - Linear
     - one-hot
     - 60,962
     - 25
     - 437.9
     - 488.9
     - 670.7
     - 76.7
   * - Linear
     - Espresso
     - 33
     - 38,498
     - 5,693.7
     - 382.1
     - 300.5
     - 56.7

On this single-S-box workload Espresso trades many constraints for dramatically
fewer binary variables, smaller LP exports, lower GLPK memory, and lower solve
times after the one-time validation. One workload is not sufficient to change
the portable one-hot default.

``WordwiseXorDifference.xor_many`` preserves known-term cancellation, including
recovery of a lone nonzero term. ``propagate_dense_wordwise_activity`` retains
the legacy 256-row model-5 abstraction only for a field-linear layer whose
coefficients are proven nonzero. It does not apply to rings with zero divisors,
does not assume exact joint support, and is distinct from branch-number
activity tables. S-box undisturbed outputs likewise carry no probabilities.

ARX linear transitions
----------------------

Modular addition has a separate exact linear-mask lowering. Integer parity
variables express the XOR recurrence, while binary variables represent the
masks and unary correlation weight:

.. doctest::

   >>> from claasp.representations.constraints.milp import ModularAddLinearMILPModel
   >>> addition = ModularAddLinearMILPModel(16)
   >>> arx_model = addition.milp_model(left_mask=0x6081, right_mask=0x40c1, output_mask=0x4081)
   >>> (len(arx_model.variables), len(arx_model.constraints))
   (79, 124)

GLPK integration restores the four modular-add transitions of the legacy
four-round Speck32/64 weight-3 characteristic, including weights
``2 + 0 + 0 + 1`` and signs ``+,+,+,-``. Decoding recomputes each correlation
with the shared exact Walsh semantics.

Qualified legacy evidence
-------------------------

Fixed legacy results retain an explicit claim kind when their original model
cannot honestly be reproduced as an exact portable proof.  This keeps exact
values separate from lower bounds, abstractions, sampled observations, and
solver regressions:

.. doctest::

   >>> from claasp.semantics.cryptanalysis import legacy_wordwise_active_sbox_evidence
   >>> activity = legacy_wordwise_active_sbox_evidence()
   >>> activity.aes_exact
   (1, 5, 9, 25)
   >>> (activity.ublock_decomposed_lower_bounds, activity.ublock_published_exact)
   ((1, 6), (1, 8, 13))

The reduced-AES wordwise-impossible fixture likewise records an abstract
incompatibility witness rather than claiming a concrete field-valued
differential proof:

.. doctest::

   >>> from claasp.semantics.cryptanalysis import legacy_wordwise_impossible_fixture
   >>> impossible = legacy_wordwise_impossible_fixture()
   >>> (impossible.input_pattern, impossible.output_pattern)
   ('1003000000000000', '1000000000000000')
   >>> impossible.claim_kind
   'abstract-incompatibility-witness'

An executed uBlock solver regression is available with the same qualification
until a typed uBlock catalogue primitive can independently reproduce it:

.. doctest::

   >>> from claasp.analysis import ublock_three_round_legacy_cluster
   >>> cluster = ublock_three_round_legacy_cluster()
   >>> (cluster.trail_count, cluster.aggregate_weight, cluster.claim_kind)
   (8, 25.7146, 'legacy-solver-regression')

Permanently license-skipped proprietary expectations are not evidence.  They
remain in the migration matrix for provenance but are not promoted to v5
oracle values.
