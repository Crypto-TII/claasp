Semantics, representations, and drivers
=======================================

CLAASP separates what graph values *mean* from how a problem is represented
and which tool processes it:

.. code-block:: text

   SemanticType -> Representation -> Driver -> Result

The selected semantic type says what flows through the graph: concrete
values, XOR differences, linear masks, truncated states, symbolic expressions,
or simulated leakage. A representation may be
CNF, SMT-LIB, MILP, source code, or a diagram. A driver may be a direct Python
interpreter, solver, compiler, or renderer.

The word ``target`` is reserved for the goal of an attack:

.. doctest::

   >>> from claasp.analysis import AttackTarget
   >>> AttackTarget.KEY_RECOVERY.value
   'key_recovery'

Graph annotations
-----------------

Different semantic types attach different information to the same graph.
The common immutable container validates input and component identifiers:

.. doctest::

   >>> from claasp.annotations import AnnotationEntry, AnnotationRole, ExecutionTrace, GraphAnnotation
   >>> from claasp.primitives import Present
   >>> from claasp.semantics import CONCRETE
   >>> primitive = Present(number_of_rounds=1)
   >>> annotation = GraphAnnotation(primitive, CONCRETE, (
   ...     AnnotationEntry("plaintext", AnnotationRole.INPUT, 0),
   ...     AnnotationEntry(primitive.graph.components[0].component_id, AnnotationRole.COMPONENT, 1),
   ... ))
   >>> trace = ExecutionTrace(annotation)
   >>> trace.value_of("plaintext")
   0

``ExecutionTrace``, cryptanalytic ``Trail``, and ``SideChannelTrace`` remain
different result types. Shared annotations allow a later diagram renderer
to consume any of them without pretending that a concrete execution is a
differential characteristic.

Cryptanalytic trail semantics live under ``claasp.semantics.cryptanalysis``;
they are not owned by SAT, SMT, or MILP. A checked trail can be attached to
its primitive for use by generic consumers:

.. doctest::

   >>> from claasp.semantics.cryptanalysis import Trail, TrailKind, TrailStep, XorDifference, SBoxTransitionSemantics
   >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
   >>> component = next(item for item in primitive.graph.components if item.component_id == "sbox_1_0")
   >>> transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(1, 3)
   >>> trail = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(1 << 60, 64), XorDifference(0, 64), (TrailStep(component.component_id, transition),))
   >>> trail.semantics.name
   'xor_differential'
   >>> trail.annotate(primitive).value_of(component.component_id) == transition
   True

Representations and artifacts
-----------------------------

A representation describes a format; an artifact is one concrete instance
with provenance:

.. doctest::

   >>> from claasp.representations import Artifact, Representation
   >>> smtlib = Representation("smtlib2", "application/smtlib")
   >>> artifact = Artifact(smtlib, "(check-sat)\n", ("xor_differential",))
   >>> artifact.provenance
   ('xor_differential',)

Drivers consume representations. The common protocols intentionally support
both ``execute(artifact)`` and solver-oriented ``solve(representation)``;
direct interpreters do not acquire artificial exporter stages merely to make
all directories look identical.

Direct execution
----------------

Concrete scalar and batch execution live under the execution representation,
with explicit Python drivers. The scalar result contains the same immutable
annotation used by ``ExecutionTrace``:

.. doctest::

   >>> from claasp.primitives import AES
   >>> from claasp.representations.execution import ScalarExecutionDriver
   >>> primitive = AES(number_of_rounds=1)
   >>> result = ScalarExecutionDriver().evaluate(primitive, {
   ...     "plaintext": tuple(bytes(16)), "key": tuple(bytes(16))
   ... })
   >>> result.trace.annotation.semantics.name
   'concrete'
   >>> len(result.trace.annotation.entries) == len(primitive.graph.input_ports) + len(primitive.graph.components) + 1
   True

Normal users continue to write ``primitive.evaluate(plaintext, key)``. The
explicit driver is primarily an extension point and a way to request the
complete execution trace.

Constraint representations
--------------------------

Constraint formats are grouped under ``representations.constraints``. For
example, CNF construction, lowering, and DIMACS export live in the SAT
representation package, while MiniSat is an external solver driver:

.. doctest::

   >>> from claasp.representations.constraints.sat import CNFFormula
   >>> from claasp.representations.constraints.sat.exporters import DimacsExporter
   >>> formula = CNFFormula(("x",), ((1,),), ("example",))
   >>> DimacsExporter().export(formula).startswith("c 1 x\np cnf 1 1")
   True

The representation can therefore be constructed and inspected on ordinary
CPython even when MiniSat is not installed. ``claasp.drivers.solvers``
contains optional process drivers and their decoded results.

SMT follows the same boundary: ``representations.constraints.smt`` owns the
portable formula, trail lowering, transition lowering, and SMT-LIB exporter;
``drivers.solvers.Z3Solver`` executes that representation. A solver driver may
accept more than one compatible representation, but it does not define their
cryptanalytic semantics.

MILP follows this boundary as well. Its immutable linear model, LP exporter,
and trail lowerings live in ``representations.constraints.milp``; GLPK process
execution and portable MILP result decoding live in ``drivers.solvers``.

Constraint-model provenance
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every backend-specific component encoding declares structured provenance.
``VERIFIED`` means that its exact constraints have been checked against a
primary source and records a URL or DOI plus a precise locator. Direct or
exhaustively generated encodings use ``N/A``. Encodings awaiting a separate
literature audit use ``TBD``; that status must not be replaced by a citation
to a paper that only introduces the surrounding cryptanalytic technique.

The declaration follows the constraints through backend lowering. Applications
also record which graph components used that encoding:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> from claasp.representations.constraints.sat import BooleanCNFModel
   >>> formula = BooleanCNFModel(Speck(number_of_rounds=1)).cnf_formula()
   >>> additions = [item for item in formula.constraint_models
   ...              if item.model.component_model == "ModularAddFunctionalSATModel"]
   >>> additions[0].model.reference_status.value
   'N/A'
   >>> additions[0].component_ids
   ('modular_add_0_1',)

Trail searches retain these applications in ``TrailSearchResult``. Presentation
adapters render the model-emitted compact reference beside each modeled
component and deduplicate any ``VERIFIED`` records into the report bibliography.
Neither the trail semantics nor the presentation layer guesses a source.

Sparse polynomial systems and their Singular/msolve serializers live in
``representations.constraints.polynomial``. The optional executable processes
are reusable ``SingularDriver`` and ``MsolveDriver`` objects under
``drivers.algebra``; a serializer can therefore be tested without installing
either computer algebra system.

Shared propagation problems
---------------------------

``PropagationProblem`` fixes cryptanalytic meaning before choosing a
constraint representation. It carries graph scope, objective, optional weight
bound, semantic registry, and provenance. Its immutable registry provides
reviewed defaults for bit-vector S-boxes and modular addition and supports
global or per-component replacement. Representation compilers consume this
problem directly. The PRESENT SMT and MILP compilers share registry-selected
component semantics; their primitive-first constructors are convenience wrappers
which create an equivalent propagation problem.

Primitive realizations are separate from execution engines
----------------------------------------------------------

A realization is a typed graph for one mathematical primitive. It is not an
execution engine: AES lookup and algebraic graphs are realizations, whereas
Python, NumPy, C, and CUDA are potential engines that execute a compatible
graph. ``RealizationDescriptor`` publishes capabilities and structural
features so a task can select deterministically without inspecting component
names.

Explicit user selection always takes precedence. Task-directed selection must
fail when no realization supplies every requested capability, and results
retain the descriptor through their evaluated graph. Equivalent realizations
share boundary semantics but may have unrelated internal component identities;
trails and traces therefore pin their realization rather than attempting an
implicit component-by-component translation.

``RealizationDescriptor`` contains the stable local name, declared
capabilities, structural features, maturity, provenance, and preference
priority. ``Primitive.realize(name, **parameters)`` performs explicit
selection. ``Primitive.for_capabilities(requirements, policy=...)`` supports
``preferred`` and ``unique`` policies; equal preferred priorities are an
error, as is a non-unique match under ``unique``.

.. doctest::

   >>> from claasp.graph import AmbiguousRealizationError
   >>> from claasp.primitives import AES
   >>> AES.for_capabilities({"scalar_evaluation"}).realization.name
   'lookup'
   >>> try:
   ...     AES.for_capabilities({"scalar_evaluation"}, policy="unique")
   ... except AmbiguousRealizationError as error:
   ...     "unique policy" in str(error)
   True

Boundary normalization, when required, uses explicit MSB-first typed bindings
around the selected graph. These conversions are wiring metadata rather than
cryptographic components. Normalization does not rewrite component identifiers
to resemble another realization and does not imply trace correspondence.

Produced results use ``ResultProvenance``. The selected graph descriptor and
the ``DriverIdentity`` are separate fields:

.. doctest::

   >>> primitive = AES(number_of_rounds=1, realization="algebraic")
   >>> result = primitive.evaluate_with_trace(plaintext=0, key=0)
   >>> result.provenance.realization.name
   'algebraic'
   >>> result.provenance.driver.name
   'python_scalar'
   >>> result.provenance.realization_identity
   'aes:algebraic'
