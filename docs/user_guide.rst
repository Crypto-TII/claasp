CLAASP User Guide
=================

CLAASP helps primitive designers and cryptanalysts describe primitives, evaluate
test vectors, and run reproducible analyses. This guide concentrates on those
tasks. It does not require users to learn backend representations or the
internal compilation pipeline.

Start with AES and the input/output conventions, then use the authoring and
analysis guides for your own work.

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
   :caption: Advanced primitive manipulation

   customizing_aes
   parameters
   primitive_authoring
   composite_blocks
   transformations
   batch_evaluation

.. toctree::
   :maxdepth: 2
   :caption: Advanced primitive analysis

   analysis
   component_properties
   displaying_results
   serialization_and_source
   statistical_testing
   neural_distinguishers

.. toctree::
   :hidden:

   implementing_toy_spn
