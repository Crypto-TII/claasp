XOR differential trails: advanced
=================================

Find an optimal differential trail
----------------------------------

In a first example, let's see how to find an optimal differential trail.
By default, CLAASP v5 uses the Kissat SAT solver for this search.

Load modules and instantiate the primitive
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, let us load the necessary module and instantiate the
primitive representing the analyzed construction.

.. code-block:: python

   from claasp.primitives import Speck

   speck = Speck(number_of_rounds=2)

Solve optimization model
~~~~~~~~~~~~~~~~~~~~~~~~

By default, the search is set in a single-key setting: the key
difference is set to zero and the plaintext difference is nonzero.

.. code-block:: python

   trail = speck.analysis.find_lowest_weight_xor_differential_trail()

The ``trail`` variable contains the search result, including the
intermediate differences and their corresponding weights.

Display solution report
~~~~~~~~~~~~~~~~~~~~~~~

You can display the resulting trail using the ``to_terminal()``
method.

.. code-block:: python

   trail.to_terminal()


For this two-round instance of SPECK, the search finds an
optimal differential trail with total weight 1.

An example output is:

.. code-block:: text

   Trail

   Round trail

   Round | Difference | Relative probability | Cumulative probability
   ------+------------+----------------------+-----------------------
   input | 0x00408000 |                  1/1 |                    1/1
       1 | 0x00000002 |                  1/1 |                    1/1
       2 | 0x0002000a |                  1/2 |                    1/2

   Proved optimal.

   Total weight: 1.

The report shows the input difference, the differences
after each round, and their relative and cumulative
probabilities.

The relative probability describes the contribution of
each round, while the cumulative probability represents
the product of the probabilities up to that round.

In this example, the final cumulative probability is 1/2,
corresponding to a total weight of 1.

The message ``Proved optimal`` confirms that no
differential trail with a lower weight exists under
the specified constraints.


How to select a solver
----------------------

CLAASP provides a catalogue of supported solver drivers.
You can use it to inspect which solvers are available
in the current environment.

.. code-block:: python

   from claasp.catalogue import catalogue

   catalogue.solvers(view="both").to_terminal()

An example output is:

.. code-block:: text

   Solver           | Driver              | Dependency       | Available | Detection evidence
   -----------------+---------------------+------------------+-----------+------------------------
   cryptominisat    | CryptoMiniSatSolver | cryptominisat5   | yes       | /usr/bin/cryptominisat5
   glpk             | GLPKSolver          | glpsol           | yes       | /usr/bin/glpsol
   ...

The availability status depends on the current environment.

The catalogue displays the registered solvers, their drivers,
dependencies, and availability status.

Solver availability does not guarantee compatibility with
every analysis method or constraint representation.

For example, we can explicitly select GLPK instead of the
default Kissat solver.

.. code-block:: python

   from claasp.drivers.solvers.glpk import GLPKSolver

   trail_glpk = speck.analysis.find_lowest_weight_xor_differential_trail(
       solver=GLPKSolver()
   )

   trail_glpk.to_terminal(details=True)

The detailed report includes the following results:

.. code-block:: text

   Input:         0x00102000
   Output:        0x80008002
   Total weight:  1
   Optimality:    proved optimal
   Search method: exact SAT optimization by binary search
   Solver:        GLPKSolver

In this example, GLPK is used as a solver backend for the
SAT-based optimization search.

The solver must be compatible with the constraint representation
used by the search method. Specifying GLPK changes the solver
backend, but not the underlying SAT formulation.

The search finds an optimal differential trail with total
weight 1, corresponding to a probability of 1/2.

Different solvers may return different optimal trails with
the same total weight.


Using Matsui bounds
-------------------

CLAASP supports Matsui-bound constraints to improve
the efficiency of differential trail searches.

These constraints provide certified lower bounds on
the weights of consecutive round windows, potentially
reducing the search space.

For example, we can use three-round ToySpeck with
the SAT backend.

.. code-block:: python

   from claasp.primitives import ToySpeck

   result = ToySpeck(3).analysis.find_optimal_trail(
       backend="sat",
       matsui_bounds=[0, 0],
       log_file="search.jsonl"
   )

   result.to_terminal()

An example output is:

.. code-block:: text

   Trail

   Round trail

   Round | Difference | Relative probability | Cumulative probability
   ------+------------+----------------------+-----------------------
   input | 0x91       |                  1/1 |                    1/1
       1 | 0x80       |                  1/2 |                    1/2
       2 | 0x88       |                  1/1 |                    1/2
       3 | 0x04       |                  1/1 |                    1/2

   Proved optimal.

   Total weight: 1.

The ``matsui_bounds`` parameter specifies certified lower
bounds for consecutive round windows of different lengths.

For three-round ToySpeck, the two values correspond to
windows of one and two rounds. Here, both bounds are zero,
which is always safe but does not further restrict the search.

The ``log_file`` parameter records information about
the search in a JSON Lines file.

Each entry contains information such as the queried
objective, solver status, runtime, and any proved
strict lower bound.

In this example, the search finds an optimal differential
trail with total weight 1, corresponding to a probability
of 1/2.


Further usages of to_terminal()
-------------------------------

The ``to_terminal()`` method can be used to display
different levels of detail about a differential trail.

By default, it displays a summary of the trail, including
the differences and probabilities for each round.

.. code-block:: python

   trail.to_terminal()

To display additional information about the individual
component transitions, we can set ``details=True``.

.. code-block:: python

   trail.to_terminal(details=True)

The detailed report includes the input and output
differences of each component, their probabilities and
weights, and information about the solver used.

The report can also be written to a text file using
the ``file`` parameter.

.. code-block:: python

   with open("trail_report.txt", "w", encoding="utf-8") as f:
       trail.to_terminal(details=True, file=f)


Weight plot
-----------

The ``plot()`` method can be used to visualize
the weight distribution of a differential trail.

.. plot::
   :context: reset
   :include-source:

   from claasp.primitives import Speck

   speck = Speck(number_of_rounds=2)
   trail = speck.analysis.find_lowest_weight_xor_differential_trail()
   trail.plot()

The plot shows the relative weight contributed by
each round and the cumulative weight of the trail.

The final cumulative weight corresponds to the
total weight of the trail.


Trail enumeration
-----------------

It is also possible to enumerate differential trails satisfying
a given weight bound.

In this example, we search for differential trails of SPECK
with a total weight at most 1.

We limit the number of returned trails to 3.

.. code-block:: python

   trails = speck.analysis.find_all_xor_differential_trails_with_weight_at_most(
       1, limit=3
   )

   print("Number of trails:", len(trails.trails))

   for i, candidate in enumerate(trails.trails, start=1):
       inputs = dict(candidate.input_differences)
       print(f"Trail {i}:")
       print(f"  Input difference: {inputs['plaintext']:#010x}")
       print(f"  Output difference: {candidate.output_difference:#010x}")

In this example, the search returns three differential trails
with different input and output differences.

An example output is:

.. code-block:: text

   Number of trails: 3
   Trail 1:
     Input difference: 0x00408000
     Output difference: 0x0002000a
   Trail 2:
     Input difference: 0x00102000
     Output difference: 0x80008002
   Trail 3:
     Input difference: 0x00400000
     Output difference: 0x81008102

The ``maximum_weight`` argument specifies the upper bound
on the trail weight, while ``limit`` specifies the maximum
number of trails to return.

Setting ``limit=3`` does not imply that only three trails
satisfy the weight bound.


Find a trail of a given weight
------------------------------

It is also possible to search for a differential trail with
a fixed weight.

In this example, we use three-round SPECK and search for
a differential trail with total weight 7 in a single-key setting.

.. code-block:: python

   speck3 = Speck(number_of_rounds=3)

   fixed_weight_trail = speck3.analysis.find_one_xor_differential_trail_with_fixed_weight(
       7
   )

   print("Total weight:", fixed_weight_trail.total_weight)
   print("Input differences:", dict(fixed_weight_trail.input_differences))
   print("Output difference:", hex(fixed_weight_trail.output_difference))

An example output is:

.. code-block:: text

   Total weight: 7.0
   Input differences: {'plaintext': 16777218, 'key': 0}
   Output difference: 0x10e81048

A total weight of 7 corresponds to a trail probability
of :math:`2^{-7}`, or 1/128.

By default, the search uses a single-key setting, where
the key difference is zero and the plaintext difference
is nonzero.

The ``input_differences`` attribute contains the plaintext
and key differences, while ``output_difference`` contains
the resulting output difference.


Find a trail starting from a fixed difference
---------------------------------------------

It is also possible to search for a differential trail
starting from a fixed input difference.

In this example, we use three-round SPECK and fix the
plaintext difference to ``0x82c08101``.

We search for a differential trail with total weight 7
in a single-key setting.

.. code-block:: python

   trail_fixed_input = speck3.analysis.find_one_xor_differential_trail_with_fixed_weight(
       7,
       fixed_input_differences={"plaintext": 0x82c08101}
   )

   inputs = dict(trail_fixed_input.input_differences)

   print("Input differences:", inputs)
   print("Output difference:", hex(trail_fixed_input.output_difference))
   print("Total weight:", trail_fixed_input.total_weight)

An example output is:

.. code-block:: text

   Input differences: {'plaintext': 2193654017, 'key': 0}
   Output difference: 0x10005000
   Total weight: 7.0

The ``fixed_input_differences`` parameter specifies the
differences to impose on the primitive inputs.

The search returns a trail with total weight 7 and the
specified plaintext difference.

In this example, the resulting output difference is
``0x10005000``.

Related-key differential trails
-------------------------------

CLAASP also supports related-key differential trail searches.

In a single-key setting, the key difference is zero.
In a related-key setting, the key difference is nonzero,
allowing the search to consider differences in the key.

In this example, we use three-round SPECK and search for
a related-key differential trail with total weight 7.

.. code-block:: python

   related_key_trail = speck3.analysis.find_one_xor_differential_trail_with_fixed_weight(
       7, nonzero_input="key"
   )

   print("Total weight:", related_key_trail.total_weight)
   print("Input differences:", dict(related_key_trail.input_differences))
   print("Output difference:", hex(related_key_trail.output_difference))

An example output is:

.. code-block:: text

   Total weight: 7.0
   Input differences: {'plaintext': 131072, 'key': 18446462599270630400}
   Output difference: 0x81008000

The ``nonzero_input="key"`` parameter requires a nonzero
key difference, but does not fix its value.

The search returns a trail with total weight 7,
corresponding to a probability of :math:`2^{-7}`.

The plaintext difference may also be nonzero.