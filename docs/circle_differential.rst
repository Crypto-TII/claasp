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
       declared circle operation.
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
the shared evaluator.
Use ``primitive.analysis.find_lowest_weight_circle_differential_trail(...)``
for the standard search workflow.

For characteristic search without enumerating plaintexts, select
``backend="sat"`` (or ``"smt"`` / ``"milp"``) and explicitly fix the other
inputs. CLAASP constructs an equivalent graph in circle coordinates and reuses
its XOR trail optimizer. A characteristic's component probability product needs
separate endpoint verification before it can support an attack claim. The
:doc:`advanced guide <advanced_circle_differential>` explains the search scope
and lists tested configurations and published small-domain results.

.. toctree::
   :maxdepth: 2

   Basic <basic_circle_differential>
   Advanced <advanced_circle_differential>
   Verification <verification_circle_differential>

.. _circle-differential-origins:

Origins and references
----------------------

The alternative-addition approach used here grew out of differential
cryptanalysis. These papers develop alternative-difference attacks on XOR-based
block ciphers, extend them to parallel operations, and provide the binary-bibrace
framework used by CLAASP:

* Roberto Civino, Céline Blondeau and Massimiliano Sala,
  `Differential attacks: using alternative operations
  <https://doi.org/10.1007/s10623-018-0516-z>`_, *Designs, Codes and
  Cryptography* 87, 225–247 (2019; published online in 2018): develops
  differential attacks using alternative additions and demonstrates a block cipher
  that is weaker under these differences than under XOR differences.
* Marco Calderini, Roberto Civino and Riccardo Invernizzi,
  `Differential experiments using parallel alternative operations
  <https://doi.org/10.1515/jmc-2023-0030>`_, *Journal of Mathematical
  Cryptology* 18(1), article 20230030 (2024): extends the experiments to
  alternative operations acting in parallel across the S-boxes.
* Roberto Civino and Valerio Fedele,
  `Binary Bibraces and Applications to Cryptography
  <https://doi.org/10.1007/s00009-024-02793-z>`_, *Mediterranean Journal of
  Mathematics* 22, article 29 (2025): introduces binary bibraces for
  understanding alternative-difference propagation through primitive layers.
