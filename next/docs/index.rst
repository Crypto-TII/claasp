CLAASP 5
========

CLAASP is a library for describing, evaluating, and analyzing symmetric
cryptographic primitives. Version 5 introduces typed logical units so that a
cipher graph can operate natively on bits, binary extension fields, or prime
fields.

The next-generation implementation is intentionally independent of SageMath.
Computer-algebra and solver integrations will be optional backends.

.. toctree::
   :maxdepth: 2
   :caption: User guide

   getting_started
   concepts
   polynomial_models
   api

Development status
------------------

The temporary distribution and import names are ``claasp-next`` and
``claasp_next``. They will become ``claasp`` when the v5 implementation
replaces the legacy package.
