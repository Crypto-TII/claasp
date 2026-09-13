Interpretations, representations, and drivers
==============================================

CLAASP separates what graph values *mean* from how a problem is represented
and which tool processes it:

.. code-block:: text

   Interpretation -> Representation -> Driver -> Result

An interpretation may describe concrete values, XOR differences, linear
masks, symbolic expressions, or simulated leakage. A representation may be
CNF, SMT-LIB, MILP, source code, or a diagram. A driver may be a direct Python
interpreter, solver, compiler, or renderer.

The word ``target`` is reserved for the goal of an attack:

.. doctest::

   >>> from claasp_next.analysis import AttackTarget
   >>> AttackTarget.KEY_RECOVERY.value
   'key_recovery'

Graph annotations
-----------------

Different interpretations attach different information to the same graph.
The common immutable container validates input and component identifiers:

.. doctest::

   >>> from claasp_next.annotations import AnnotationEntry, AnnotationRole, ExecutionTrace, GraphAnnotation
   >>> from claasp_next.ciphers import PresentBlockCipher
   >>> from claasp_next.interpretations import CONCRETE
   >>> cipher = PresentBlockCipher(number_of_rounds=1)
   >>> annotation = GraphAnnotation(cipher, CONCRETE, (
   ...     AnnotationEntry("plaintext", AnnotationRole.INPUT, 0),
   ...     AnnotationEntry(cipher.components[0].component_id, AnnotationRole.COMPONENT, 1),
   ... ))
   >>> trace = ExecutionTrace(annotation)
   >>> trace.value_of("plaintext")
   0

``ExecutionTrace``, cryptanalytic ``Trail``, and ``SideChannelTrace`` remain
different semantic types. Shared annotations allow a later diagram renderer
to consume any of them without pretending that a concrete execution is a
differential characteristic.

Cryptanalytic trail semantics live under ``interpretations.cryptanalysis``;
they are not owned by SAT, SMT, or MILP. A checked trail can be attached to
its cipher for use by generic consumers:

.. doctest::

   >>> from claasp_next.interpretations.cryptanalysis import Trail, TrailKind, TrailStep, XorDifference, SBoxTransitionSemantics
   >>> from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX
   >>> component = next(item for item in cipher.components if item.component_id == "sbox_1_0")
   >>> transition = SBoxTransitionSemantics(PRESENT_SBOX).xor_differential(1, 3)
   >>> trail = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(1 << 60, 64), XorDifference(0, 64), (TrailStep(component.component_id, transition),))
   >>> trail.interpretation.name
   'xor_differential'
   >>> trail.annotate(cipher).value_of(component.component_id) == transition
   True

Representations and artifacts
-----------------------------

A representation describes a format; an artifact is one concrete instance
with provenance:

.. doctest::

   >>> from claasp_next.representations import Artifact, Representation
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

   >>> from claasp_next.ciphers import AESBlockCipher
   >>> from claasp_next.representations.execution import ScalarExecutionDriver
   >>> cipher = AESBlockCipher(number_of_rounds=1)
   >>> result = ScalarExecutionDriver().evaluate(cipher, {
   ...     "plaintext": tuple(bytes(16)), "key": tuple(bytes(16))
   ... })
   >>> result.trace.annotation.interpretation.name
   'concrete'
   >>> len(result.trace.annotation.entries) == len(cipher.inputs) + len(cipher.components) + 1
   True

Normal users continue to write ``cipher.evaluate(plaintext, key)``. The
explicit driver is primarily an extension point and a way to request the
complete execution trace.

Constraint representations
--------------------------

Constraint formats are grouped under ``representations.constraints``. For
example, CNF construction, lowering, and DIMACS export live in the SAT
representation package, while MiniSat is an external solver driver:

.. doctest::

   >>> from claasp_next.representations.constraints.sat import CNFFormula
   >>> from claasp_next.representations.constraints.sat.exporters import DimacsExporter
   >>> formula = CNFFormula(("x",), ((1,),), ("example",))
   >>> DimacsExporter().export(formula).startswith("c 1 x\np cnf 1 1")
   True

The representation can therefore be constructed and inspected on ordinary
CPython even when MiniSat is not installed. ``claasp_next.drivers.solvers``
contains optional process drivers and their decoded results.

SMT follows the same boundary: ``representations.constraints.smt`` owns the
portable formula, trail lowering, transition lowering, and SMT-LIB exporter;
``drivers.solvers.Z3Solver`` executes that representation. A solver driver may
accept more than one compatible representation, but it does not define their
cryptanalytic interpretation.

MILP follows this boundary as well. Its immutable linear model, LP exporter,
and trail lowerings live in ``representations.constraints.milp``; GLPK process
execution and portable MILP result decoding live in ``drivers.solvers``.

Sparse polynomial systems and their Singular/msolve serializers live in
``representations.constraints.polynomial``. The optional executable processes
are reusable ``SingularDriver`` and ``MsolveDriver`` objects under
``drivers.algebra``; a serializer can therefore be tested without installing
either computer algebra system.
