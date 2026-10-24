Input and key recovery: advanced
================================

Analysis constraints refer to primitive inputs, outputs, components, and indexed
logical units—not DIMACS or backend variable names. Problems and projected
results therefore remain meaningful when the solver changes.

.. doctest::

   >>> from claasp import PrimitiveBuilder, UnitArrayType
   >>> from claasp.analysis import AnalysisProblem, FixedValue
   >>> from claasp.components import Add
   >>> from claasp.unit_types import Bit
   >>> builder = PrimitiveBuilder("xor", {
   ...     "plaintext": UnitArrayType(Bit(), (1,)),
   ...     "key": UnitArrayType(Bit(), (1,)),
   ... })
   >>> builder.add_round()
   Round(number=0)
   >>> output = builder.add_component(Add((builder.input("plaintext"), builder.input("key"))))
   >>> primitive = builder.build(output)
   >>> problem = AnalysisProblem(
   ...     primitive,
   ...     constraints=(
   ...         FixedValue(primitive.graph.input("plaintext"), 1),
   ...         FixedValue(primitive.graph.output, 0),
   ...     ),
   ...     projections={"key": primitive.graph.input("key")},
   ... )
   >>> [type(item).__name__ for item in problem.constraints]
   ['FixedValue', 'FixedValue']

With the optional ``minisat`` executable installed, the common key-recovery
workflow is deliberately shorter:

.. code-block:: python

   result = primitive.analysis.recover_input(
       "key",
       known_inputs={"plaintext": 1},
       output=0,
   )
   assert result.is_satisfiable
   assert result.value("key") == 1

``Equal``, ``NotEqual``, ``Nonzero``, and ``HammingWeight`` provide reusable
backend-neutral constraints. ``MinimizeWeight`` records an objective, while a
backend that cannot optimize rejects it explicitly. Results retain status,
runtime, backend name, model statistics, projections, and the raw solver
result for reproducibility.

Word-oriented recovery
----------------------

The same API lowers word-native ARX operations to Boolean constraints. Inputs
and projections remain ordinary packed integers; users do not manually split
words into solver bits. For example, MiniSat can recover a key consistent with
a one-round Speck32/64 plaintext/ciphertext pair:

.. code-block:: python

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=1)
   plaintext = 0x6574694C
   ciphertext = primitive.evaluate(plaintext, 0x1918111009080100)
   result = primitive.analysis.recover_input(
       "key",
       known_inputs={"plaintext": plaintext},
       output=ciphertext,
   )
   assert result.is_satisfiable
   assert primitive.evaluate(plaintext, result.value("key")) == ciphertext

A reduced-round pair may admit several keys. Build an ``AnalysisProblem`` with
the desired key projection and call ``enumerate_solutions(problem, limit=N)``
to request distinct projected solutions. The facade adds blocking clauses and
stops either at ``N`` or when the model becomes unsatisfiable.
