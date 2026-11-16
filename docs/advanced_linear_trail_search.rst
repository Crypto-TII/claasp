XOR-linear trails: advanced
===========================

This page shows how to search for XOR-linear trails with CLAASP. The library can build the
search model in four formalisms: SAT, MILP, CP and SMT. Every search starts from the
``analysis`` attribute of a primitive, and the solver you pass with the ``solver`` parameter
selects the formalism.

All solver classes are in ``claasp.drivers.solvers``. The XOR-linear trail search provides
the following methods:

- ``find_lowest_weight_xor_linear_trail``: returns a trail of the lowest weight, together
  with the proved lower bound and the search metadata.
- ``find_one_xor_linear_trail``: returns one XOR-linear trail, optionally bounded by a
  maximum weight, without minimizing its weight.
- ``find_one_xor_linear_trail_with_fixed_weight``: returns one XOR-linear trail of a
  user-specified weight.
- ``find_all_xor_linear_trails_with_weight_at_most``: returns all XOR-linear trails up to a
  given weight, together with a flag that tells whether the enumeration is complete.

The ``find_one_*`` methods return ``None`` only when the solver proves that no such trail
exists. Solver errors are raised as exceptions and never returned as ``None``.


Find an optimal linear trail
----------------------------

Instantiate the class of the primitive to analyze and call
the search method on its ``analysis`` attribute:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   speck = Speck(number_of_rounds=3)
   trail = speck.analysis.find_lowest_weight_xor_linear_trail()

The first example finds an optimal linear trail. The default solver for the method ``find_lowest_weight_xor_linear_trail`` is Kissat; you can
select another one with the ``solver`` parameter, as described in
:ref:`linear-trail-other-solvers`. 

Terminal report
---------------

.. code-block:: python

   trail.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   trail.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_basic_terminal.txt
   :language: text

The ``Round trail`` table shows the trail one round at a time. The ``input`` row is the mask
at the input of the cipher, and rows ``1``, ``2``, ... are the masks at the output of each round.
Each mask covers the full 32-bit state, written as the two 16-bit words joined together.
``Relative correlation`` is the correlation of each round, and ``Cumulative correlation`` is
their product, that is, the correlation of the trail truncated at that round.

``Proved optimal.`` means that the solver also proved that no trail of lower weight exists for
this number of rounds. ``Total weight`` is :math:`-\log_2` of the absolute correlation of the
trail, so a weight of 1 matches the correlation :math:`1/2` above.

The ``External input patterns`` table gives the mask on each input of the cipher. The
``plaintext`` mask is the same as the ``input`` row of the ``Round trail`` table. The ``key``
mask is zero because the trail does not involve the key.

For the search evidence and the trail component by component, request the detailed
report:

.. code-block:: python

   trail.to_terminal(details=True)

The ``Trail summary`` table describes the trail as a whole and the search that produced it.
Besides the input and output patterns and the total weight, it records the proved
``lower bound`` and the ``optimality`` status: the trail is ``proved optimal`` only when the
lower bound equals the total weight. It also records the search method, the solver and its
version, the runtime and the peak memory; the last two depend on the machine.

The ``Component transitions`` table has one row for each component of each round, identified
by its component ID (for example ``modular_add_0_1``). Each row gives the input and output
patterns of the component, its exact ratio and sign, and the weight it adds to the trail; the
weights of all rows sum to the total weight. Components with several inputs show their input
patterns joined together, and ``—`` marks a component without an input pattern, such as a
constant. The constraint model reference points to the paper, section and equation behind the
model of each nonlinear component, such as modular addition; linear components are encoded
directly as Boolean clauses and show ``N/A``. The ``Citations`` section lists the full
verified references.

Mask format
~~~~~~~~~~~

The ``value_format`` parameter sets how masks are written in every table of the report,
including the detailed one. It accepts three values:

- ``"hex"``: hexadecimal, padded with leading zeros to the width of the mask (default);
- ``"binary"``: binary with the ``0b`` prefix, keeping all leading zeros;
- ``"underscore_one"``: binary without prefix, with each 0 written as ``_`` and each 1 as
  ``1``, so that active bits stand out.

In every format the most significant bit is on the left. For example:

.. code-block:: python

   trail.to_terminal(value_format="underscore_one")

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   trail.to_terminal(file=output, value_format="underscore_one")
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_basic_terminal_underscore_one.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_basic_terminal_underscore_one.txt
   :language: text

Weight plot
-----------

.. plot::
   :context: close-figs
   :include-source:

   trail.plot()

The plot shows the same trail as the table, measured as weight (:math:`-\log_2` of the absolute correlation)
instead of correlation. Round ``0`` is the input of the cipher. The ``Relative weight`` line is the
weight added by each round, and the ``Cumulative weight`` line is the sum of the weights so far.
The last point of the cumulative line equals the ``Total weight`` of the report. A round with
weight 0 is deterministic, and a steep segment shows the round that costs the most.

To save the plot or create it without displaying it, use the ``save_to`` and ``show``
parameters, as described in :doc:`basic_linear_trail_search`.

Trail enumeration
-----------------

The trail found above has weight 1. The following example enumerates all the trails of weight 1.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   speck = Speck(number_of_rounds=3)
   trails = speck.analysis.find_all_xor_linear_trails_with_weight_at_most(minimum_weight=1, maximum_weight=1)

.. code-block:: python

   trails.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   trails.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_enumeration_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_enumeration_terminal.txt
   :language: text

The ``Enumeration summary`` table gives the number of trails found and states whether the
enumeration is ``complete``, that is, whether every trail in the requested weight range was
found. It also records the primitive, the solver and the runtime.

The ``Characteristics`` table lists one trail per row, with its weight, its input mask (one value
for each cipher input, here the plaintext and the key), its output mask and the sign of its
correlation. The trail found in the previous section appears among them: different trails can
share the same input or output mask and differ only inside the cipher.

To see where each trail gets its weight, request the detailed report:

.. code-block:: python

   trails.to_terminal(details=True)

After the same two tables, the detailed report adds one table for each characteristic. It lists
the modular additions, the only nonlinear components of Speck, with their input and output
masks, the weight that each one adds and the sign of its correlation. In this example, every
trail gets its whole weight from a single modular addition, while the others have weight 0.

By default, the enumeration stops after 1000 trails. If more trails exist, the search stops
there and the ``complete`` flag is set to false.

Trail of a given weight
-----------------------
CLAASP can also find a trail of a given weight, if it exists.

.. plot::
   :context:
   :nofigs:
   :include-source:

   trail = speck.analysis.find_one_xor_linear_trail_with_fixed_weight(fixed_weight=7)

You can display the result with the ``to_terminal()`` method and the ``details`` option, as in the
previous examples.

Imposing constraints
--------------------

To restrict the search, build a ``Constraints`` object and pass it to the ``constraints``
parameter of any XOR-linear trail search method. A constraint can target an input of the
cipher (for example ``"plaintext"`` or ``"key"``), a component ID, or ``"output"``.

The following example requires both the plaintext mask and the key mask to be nonzero:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.analysis import Constraints

   active_key_and_plaintext = (
       Constraints()
       .nonzero("key")
       .nonzero("plaintext")
   )

   trail = speck.analysis.find_lowest_weight_xor_linear_trail(
       constraints=active_key_and_plaintext,
   )

.. code-block:: python

   trail.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   trail.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_constraints.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_constraints.txt
   :language: text

Both constraints hold: unlike the trail found in the first section, whose ``key`` mask is
zero, the ``key`` mask of this trail is nonzero, and the trail now involves key bits. The
price is a higher weight: the trail is ``Proved optimal`` with a total weight of 2 instead
of 1, so no trail with nonzero plaintext and key masks has weight below 2 for 3 rounds of Speck.

Two details are worth knowing:

- A constraint on a mask does not fix the value of the key. To fix concrete key values, use
  the ``fixed_inputs`` parameter.
- The default ``nonzero_input`` requirement on the plaintext mask still applies. To allow a
  zero plaintext mask together with a nonzero key mask, pass ``nonzero_input="key"``.

Other constraints
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 35 45

   * - Method
     - Meaning
     - Example
   * - ``zero``
     - All selected bits are zero
     - ``.zero("key")``
   * - ``nonzero``
     - At least one selected bit is one
     - ``.nonzero("plaintext")``
   * - ``equal``
     - Equal a packed integer value
     - ``.equal("plaintext", 0x80)``
   * - ``not_equal``
     - Differ from a packed integer value
     - ``.not_equal("output", 0x01)``
   * - ``hamming_weight``
     - Exact number of set bits
     - ``.hamming_weight("key", exactly=2)``
   * - ``hamming_weight``
     - Inclusive bounds on set bits
     - ``.hamming_weight("output", minimum=1, maximum=4)``

Every method also accepts ``bit_positions`` to constrain only selected bits.
Positions are **zero-based, most-significant bit first**:

.. code-block:: python

   constraints = (
       Constraints()
       .nonzero("plaintext")
       .hamming_weight("key", exactly=2)
       .zero("plaintext", bit_positions=(0, 1, 2))
   )

.. _linear-trail-other-solvers:

Other solvers
-------------

By default, ``find_lowest_weight_xor_linear_trail`` builds a SAT model and solves it with
Kissat. You can select another solver with the ``solver`` parameter.

The catalogue lists every solver that CLAASP can drive.

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.catalogue import catalogue

   supported = catalogue.solvers()
   supported.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   supported.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_solvers.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_solvers.txt
   :language: text

Being listed in the catalogue does not mean that a solver is installed. CLAASP does not
include these solvers: depending on the solver, it relies on an executable on your ``PATH``
or on an installed Python package. The ``view`` parameter controls the availability check:
``"both"``, as in the example below, compares the solvers supported by CLAASP with those
installed on your machine, and ``"available"`` shows only the solvers installed on your machine.

.. plot::
   :context:
   :nofigs:
   :include-source:

   catalogue.solvers(view="both").to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   catalogue.solvers(view="both").to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_available_solvers.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_available_solvers.txt
   :language: text

The ``implementation`` field of each solver gives the module and the class that implement its
driver. This tells you what to import:

.. plot::
   :context:
   :nofigs:
   :include-source:

   [entry.implementation
      for entry in catalogue.solvers().entries
      if entry.name == "cryptominisat"]

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   print([entry.implementation for entry in catalogue.solvers().entries if entry.name == "cryptominisat"], file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_solvers_import.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_solvers_import.txt
   :language: text

Import the solver class and pass an instance of it as the ``solver`` parameter. For example,
the following command finds the lowest-weight trail with CryptoMiniSat:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.drivers.solvers import CryptoMiniSatSolver

   trail = speck.analysis.find_lowest_weight_xor_linear_trail(solver=CryptoMiniSatSolver())
