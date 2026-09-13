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
