CLAASP documentation
====================

CLAASP is a Python workbench for implementing, evaluating, and analyzing
symmetric cryptographic primitives. Primitive descriptions stay close to their
pseudocode and can be reused by evaluators and cryptanalytic backends.

Start with a standard AES evaluation, then follow the task-oriented guides to
implement or analyze a primitive. SageMath is not required; computer-algebra
systems and solvers are optional backends.

.. toctree::
   :maxdepth: 2
   :caption: Start here

   getting_started
   quick_analysis_scripts
   implementing_toy_spn
   primitive_authoring
   analysis
   traditional_primitives
   primitive_catalogue
   batch_evaluation

.. toctree::
   :maxdepth: 2
   :caption: CLAASP 5 and AO primitives

   whats_new_v5
   concepts
   parameters

.. toctree::
   :maxdepth: 2
   :caption: Advanced modeling

   polynomial_models
   boolean_models
   smt_models

.. toctree::
   :maxdepth: 2
   :caption: Reference and development

   development
   catalogue_architecture
   api
