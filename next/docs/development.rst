Development and testing
=======================

Worktree layout
---------------

The legacy and v5 branches can be checked out simultaneously. In the current
development workspace they are located at:

.. code-block:: text

   <workspace>/symmetric_cryptanalysis_tools/claasp  legacy feature branch
   <workspace>/claasp-v5                             claasp-v5

List every active checkout with:

.. code-block:: console

   git worktree list

Opening ``symmetric_cryptanalysis_tools/claasp`` therefore shows the legacy
branch by design. Open the ``claasp-v5`` worktree as a separate editor window
to inspect the new implementation.

Running tests
-------------

From the ``next`` directory, run the dependency-free unit suite:

.. code-block:: console

   PYTHONPATH=src pytest -q -c pyproject.toml

Run executable examples embedded in public Python APIs:

.. code-block:: console

   PYTHONPATH=src pytest -q --doctest-modules src/claasp_next -c pyproject.toml

Run both documentation suites:

.. code-block:: console

   make -C docs doctest

Building the documentation
--------------------------

Build both independent HTML sites, treating warnings as failures:

.. code-block:: console

   make -C docs html

On macOS, open it with:

.. code-block:: console

   open docs/_build/user/user_guide.html
   open docs/_build/developer/developer_guide.html

The ``docs`` optional dependency group installs Sphinx and the Furo theme:

.. code-block:: console

   python -m pip install -e '.[dev,docs]'

Testing Singular export
-----------------------

When Singular is on ``PATH``, the normal unit suite executes the generated
program and verifies that Singular accepts it. Otherwise that one integration
test is skipped. CI has a dedicated job that installs Singular and always runs
the integration.

Benchmarking batch evaluation
-----------------------------

Compare the scalar-loop reference with the one-traversal backend using:

.. code-block:: console

   PYTHONPATH=src python tools/benchmark_batch.py --batch-size 32

Timings are deliberately not asserted in CI because shared runners are noisy.
