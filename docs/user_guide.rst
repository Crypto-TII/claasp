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
   :caption: Basic Primitive Analysis

   basic_primitive_analysis
   basic_avalanche_analysis
   basic_continuous_diffusion
   basic_component_analysis

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
   advanced_component_analysis

.. toctree::
   :maxdepth: 2
   :caption: Temporary section

   analysis
   component_properties
   displaying_results
   serialization_and_source
   statistical_testing
   neural_distinguishers
