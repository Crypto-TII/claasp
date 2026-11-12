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
---------------------------------------

As a first example, let's see how to find an optimal linear trail. 
The default solver is ``Kissat``, but other solvers can be selected using the ``solver`` parameter. 
To know more about specifing solvers see :ref:`linear-trail-external-solvers`.  
First, instantiate the class representing the analyzed primitive:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   speck = Speck(number_of_rounds=3)
   trail = speck.analysis.find_lowest_weight_xor_linear_trail()

Terminal report
---------------------

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

.. plot::
   :context: close-figs
   :include-source:

   trail.plot()

The plot shows the same trail as the table, measured as weight (:math:`-\log_2` of the probability)
instead of probability. Round ``0`` is the input of the cipher. The ``Relative weight`` line is the
weight added by each round, and the ``Cumulative weight`` line is the sum of the weights so far.
The last point of the cumulative line equals the ``Total weight`` of the report. A round with
weight 0 is deterministic, and a steep segment shows the round that costs the most.

Trail enumeration
-----------------

We have found a trail of weight 1. Now let's enumerate all the trails of weight 1.

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

.. _linear-trail-external-solvers:

Other solvers
----------------

By default, ``find_lowest_weight_xor_linear_trail`` builds a SAT model and solves it with
Kissat. You can select another solver with the ``solver`` parameter. The solver also sets the
formalism: if you pass a MILP solver, the same search is solved as a MILP problem, and the
trail it returns has the same optimal weight.

The catalogue lists every solver that CLAASP can drive. Each solver records the model
representations it accepts, and the names of MILP representations end with ``_milp``. The
following command lists the solvers that accept a MILP model:

.. plot::
   :context:
   :nofigs:
   :include-source:
    
   from claasp.catalogue import catalogue
   milp_solvers = [r for r in catalogue.drivers(kind="solver") if any(rep.endswith("_milp") for rep in r.representations)]
   [solver.name for solver in milp_solvers]

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   print([solver.name for solver in milp_solvers], file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_milp_solvers.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_milp_solvers.txt
   :language: text

Being listed in the catalogue does not mean that a solver is installed. CLAASP does not
include these solvers: depending on the solver, it relies on an executable on your ``PATH``
or on an installed Python package. ``catalogue.driver_availability`` checks this without
importing the solver. The following command keeps only the MILP solvers that are available
on your machine:

.. plot::
   :context:
   :nofigs:
   :include-source:
    
   [solver.name for solver in milp_solvers if catalogue.driver_availability(solver).available]

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   print([solver.name for solver in milp_solvers if catalogue.driver_availability(solver).available], file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_milp_available_solvers.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_milp_available_solvers.txt
   :language: text

The ``implementation`` field of each solver gives the module and the class that implement its
driver. This tells you what to import:

.. plot::
   :context:
   :nofigs:
   :include-source:
    
   [solver.implementation for solver in milp_solvers]

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   print([solver.implementation for solver in milp_solvers], file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_linear_trail_milp_solvers_import.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_linear_trail_milp_solvers_import.txt
   :language: text

Import the solver class and pass an instance of it as the ``solver`` parameter. For example,
the following command finds the lowest-weight trail with HiGHS, an open-source MILP solver:

.. plot::
   :context: 
   :nofigs:
   :include-source:

   from claasp.drivers.solvers import HighsSolver

   trail = speck.analysis.find_lowest_weight_xor_linear_trail(solver=HighsSolver())
