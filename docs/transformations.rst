Transformations
===============

Transformations consume an immutable typed primitive graph and return a new,
validated graph. The source primitive is never edited. Structural joins,
ordered views, ``PackBits``, and ``UnpackBits`` remain graph bindings; they do
not become semantic components or synthetic identities.



.. toctree::
   :maxdepth: 2

   transformation_inversion
   transformation_partial_inversion
   transformation_slicing
   transformation_key_schedule
   transformation_pairing
