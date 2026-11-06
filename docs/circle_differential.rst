Circle-differential trails
==========================

Circle-differential cryptanalysis studies input pairs related by an alternative
addition :math:`\circ`. In the binary bibraces supported by CLAASP, each element
is its own inverse, so addition and subtraction coincide. An input difference
:math:`a` defines the pair :math:`(x,x\circ a)`. We count how often the output
difference :math:`F(x)\circ F(x\circ a)` equals a chosen :math:`b`.

.. list-table:: XOR and circle differentials
   :header-rows: 1
   :widths: 25 35 40

   * - Concept
     - XOR differential
     - Circle differential
   * - Input pair
     - :math:`(x,x\oplus a)`
     - :math:`(x,x\circ a)`
   * - Output difference
     - :math:`F(x)\oplus F(x\oplus a)`
     - :math:`F(x)\circ F(x\circ a)`
   * - Difference representation
     - Original packed bits of :math:`a` or :math:`b`.
     - Original packed bits of :math:`a` or :math:`b`, interpreted using the
       declared circle operation. These are differences, rather than masks.
   * - Probability
     - Fraction of input pairs producing the selected output difference.
     - The same definition, with the alternative difference operation.

The primitive remains unchanged. Choosing XOR as the alternative operation
recovers ordinary XOR differentials. An S-box that resists XOR differentials
can have much stronger circle differentials. Conversely, XOR key additions
and diffusion layers need their actual circle-difference behaviour checked.

CLAASP provides exact circle-DDTs for bounded functions, exact endpoint and
concrete-trail search over bounded input domains, and sampled verification
for larger binary primitives. Concrete trail search fixes the input difference
and all other primitive inputs, then counts actual boundary histories through
the shared evaluator. It has no SAT, SMT, MILP or CP circle-differential search
backend; it does not claim an efficient exhaustive search on full-size primitives.
Use ``primitive.analysis.find_lowest_weight_circle_differential_trail(...)``
for the standard search workflow. The guides distinguish this concrete search
from a product of local DDT probabilities.

.. toctree::
   :maxdepth: 2

   Basic <basic_circle_differential>
   Advanced <advanced_circle_differential>
   Verification <verification_circle_differential>

References
----------

* Civino, Blondeau and Sala, `Differential attacks: using alternative operations
  <https://doi.org/10.1007/s10623-018-0516-z>`_, *Designs, Codes and Cryptography*
  87, 225–247 (2019): alternative-difference attacks on XOR-based block ciphers.
* Calderini, Civino and Invernizzi, `Differential experiments using parallel
  alternative operations <https://doi.org/10.1515/jmc-2023-0030>`_, *Journal of
  Mathematical Cryptology* 18(1), article 20230030 (2024): parallel operations
  and the four-bit example reproduced in these guides.
* Civino and Fedele, `Binary Bibraces and Applications to Cryptography
  <https://doi.org/10.1007/s00009-024-02793-z>`_, *Mediterranean Journal of
  Mathematics* 22, article 29 (2025): the supported algebraic framework.
