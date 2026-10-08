API reference
=============

Domains
-------

.. autoclass:: claasp.domains.base.Domain
   :members:

.. automodule:: claasp.domains
   :members:

Primitive graph
----------------

.. automodule:: claasp.graph
   :members:

Graph transformations
---------------------

.. automodule:: claasp.transformations
   :members:

Semantics and annotations
-------------------------

.. automodule:: claasp.semantics
   :members:

.. automodule:: claasp.annotations
   :members:

Representations and drivers
---------------------------

.. automodule:: claasp.provenance
   :members:

.. automodule:: claasp.representations
   :members:

.. automodule:: claasp.drivers
   :members:

Boundary encodings
------------------

.. automodule:: claasp.encoding
   :members:

Components
----------

.. automodule:: claasp.components
   :members:

Composite blocks
----------------

.. automodule:: claasp.composites
   :members:

Authoring utilities
-------------------

.. automodule:: claasp.utils
   :members:

Evaluation
----------

.. automodule:: claasp.representations.execution
   :members:

Analysis
--------

.. automodule:: claasp.analysis
   :members:
   :exclude-members: BitPattern,ModularAddLinearSemantics,ModularAddTransitionSemantics,SBoxTransitionSemantics,Trail,TrailKind,TrailRoundTransition,TrailSearchResult,TrailStep,Transition,TruncatedBit,TruncatedXorDifference,XorDifference,XorMask,propagate_two_word_speck_round,truncated_modular_add

.. automodule:: claasp.drivers.analysis
   :members:

Primitives
----------

.. automodule:: claasp.primitives
   :members:

Parameter catalogues
--------------------

.. automodule:: claasp.parameters
   :members:

Catalogue discovery
-------------------

.. automodule:: claasp.catalogue
   :members:

Presentation
------------

.. automodule:: claasp.presentation
   :members:

Constraint model provenance
---------------------------

.. automodule:: claasp.representations.constraints
   :members:

Polynomial models
-----------------

.. automodule:: claasp.representations.constraints.polynomial
   :members:

.. automodule:: claasp.representations.constraints.milp.monomial
   :members:

.. automodule:: claasp.drivers.algebra
   :members:

Boolean models
--------------

.. automodule:: claasp.representations.constraints.sat
   :members:

.. automodule:: claasp.representations.constraints.sat.exporters
   :members:
   :no-index:

.. automodule:: claasp.drivers.solvers
   :members:

SMT models
----------

.. automodule:: claasp.representations.constraints.smt
   :members:

MILP models
-----------

.. automodule:: claasp.representations.constraints.milp
   :members:

Complete public namespace index
-------------------------------

Every module that explicitly declares the public API is listed below. This
index is generated from the same mechanical authority used by the M10.16
closure gate.

.. include:: public_api_namespaces.rst
