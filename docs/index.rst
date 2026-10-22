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
   :caption: Introduction

   about_claasp
   whats_new_v5
   getting_started
   concepts

.. toctree::
   :maxdepth: 2
   :caption: Basic use

   traditional_primitives
   primitive_catalogue
   evaluating_primitives
   quick_analysis_scripts

.. toctree::
   :maxdepth: 2
   :caption: Basic Primitive Analysis

   basic_primitive_analysis
   basic_avalanche_analysis
   basic_continuous_diffusion

.. toctree::
   :maxdepth: 2
   :caption: Advanced primitive manipulation

   customizing_aes
   parameters
   primitive_authoring
   implementing_toy_spn
   composite_blocks
   transformations
   batch_evaluation

.. toctree::
   :maxdepth: 2
   :caption: Advanced primitive analysis

   advanced_primitive_analysis
   advanced_avalanche_analysis
   advanced_continuous_diffusion

.. toctree::
   :maxdepth: 2
   :caption: Temporary section

   analysis
   component_properties
   displaying_results
   serialization_and_source
   statistical_testing
   neural_distinguishers


.. toctree::
   :maxdepth: 2
   :caption: Reference and development

   development
   catalogue_architecture
   api
