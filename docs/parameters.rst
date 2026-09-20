Verified parameter catalogues
=============================

Generic permutation classes accept caller-supplied parameters and only claim
structural correctness. Each primitive package owns its concrete parameter
sets, source revision, license, schema version, and reference vectors.
``claasp.parameters`` is only a convenience re-export.

BN254 width-3 Poseidon
----------------------

The first bundled set comes from the MIT-licensed `Ingonyama Poseidon
reference implementation <https://github.com/ingonyama-zk/poseidon-hash>`_,
pinned to commit ``5194eadce26b3fe4b1c4fe2a5ca9f6436f3b0e3d``. Its upstream
test identifies the vector as originating from the original HadesHash
reference implementation.

.. doctest::

   >>> from claasp.parameters import poseidon_bn254_width3
   >>> parameters = poseidon_bn254_width3()
   >>> parameters.width, parameters.full_rounds, parameters.partial_rounds
   (3, 8, 57)
   >>> result = parameters.permutation().evaluate(parameters.reference_input)
   >>> hex(result[parameters.reference_output_position])
   '0xfca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29'

The catalogue describes the permutation state. It does not add sponge
padding, domain separation, or a hash API around that permutation.

Reproducing the import
----------------------

The bundled JSON is generated without importing or executing the upstream
package. After checking out the pinned reference repository, run:

.. code-block:: console

   python tools/import_poseidon_reference.py \
       /path/to/poseidon-hash/poseidon/parameters.py \
       src/claasp/primitives/permutations/poseidon/data/poseidon_bn254_width3.json

The importer parses only the three expected literal assignments through
Python's :mod:`ast` module. It records the source commit and upstream symbol
names in the generated file.
