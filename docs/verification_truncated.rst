Truncated XOR differences: verification
=======================================

V5 validates supported truncated characteristic witnesses. It does not expose
a general concrete-pair realizability checker or a general empirical truncated
endpoint checker.

Characteristic validation
-------------------------

``WordDeterministicTruncatedSATModel`` and
``WordwiseDeterministicTruncatedSATModel`` expose ``decode_characteristic()``
and ``check_characteristic()``. Their decoders check the solver assignment
and replay the supported three-valued or wordwise propagation rules. The
corresponding SMT, MILP and CP wrappers reuse these checks.

An unknown truncated difference denotes a set of possible differences. A valid
abstract trail need not identify one concrete pair following every abstract
state. Likewise, an abstract propagation result is not an empirical endpoint
probability. The rules and their soundness assumptions must be retained when
interpreting a result. See :doc:`advanced_truncated_differences` and
:doc:`trail_search_introduction`.
