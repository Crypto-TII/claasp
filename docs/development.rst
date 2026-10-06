Contributing to CLAASP
======================

This guide covers the checks and conventions used for ordinary contributions.
Run commands from the repository root unless a section says otherwise.

Set up a development environment
--------------------------------

CLAASP supports CPython 3.11 and later. Install the package, test runner,
documentation tools, formatter, linter, and type checker with:

.. code-block:: console

   python -m pip install -e '.[dev,docs,quality]'

Optional solver, presentation, and machine-learning dependencies are not
needed for the core test suite.

Running tests
-------------

Run the routine dependency-free suite with:

.. code-block:: console

   PYTHONPATH=src python -m pytest

Run one file or one test while developing a focused change:

.. code-block:: console

   PYTHONPATH=src python -m pytest tests/unit/domains/test_package.py
   PYTHONPATH=src python -m pytest tests/unit/domains/test_package.py::test_value_type_rejects_invalid_shapes

The configured default excludes tests marked ``external`` and ``extended``.
Run every dependency-free test, including longer exhaustive checks, with:

.. code-block:: console

   PYTHONPATH=src python -m pytest -m 'not external'

Tests marked ``external`` require a program such as a solver or computer
algebra system. Run only the relevant external test after installing that
program; CI has dedicated jobs for supported integrations. Tests marked
``performance`` assert native wall-clock budgets and are not meaningful under
emulation.

The functional tree under ``tests/unit`` mirrors ``src/claasp``. Put a test
under the narrowest source package and module that owns the behavior.
Cross-module end-to-end behavior belongs in ``tests/integration``.
``tests/unit/repository`` is the deliberate exception for repository-wide
contracts such as generated catalogues, packaging policy, CI configuration,
and release metadata.

Run executable examples in public Python docstrings with:

.. code-block:: console

   PYTHONPATH=src python -m pytest --doctest-modules src/claasp

Documentation
-------------

The user and developer guides are independent Sphinx sites. Test every RST
doctest with:

.. code-block:: console

   make -C docs doctest

Build both HTML sites, treating warnings as errors, with:

.. code-block:: console

   make -C docs html

The entry pages are then:

.. code-block:: text

   docs/_build/user/user_guide.html
   docs/_build/developer/developer_guide.html

User-guide prose should describe the current public behavior. Historical
plans, one-time migration evidence, and generated audits belong under
``docs/architecture`` and must not be linked as prerequisites for using the
library. Add executable examples for stable behavior where practical.

Formatting, linting, and typing
-------------------------------

Run the same check-only commands as CI:

.. code-block:: console

   ruff format --check src tests tools docs/conf.py
   ruff check src tests tools docs/conf.py
   python tools/typecheck_closure.py --check

Apply formatting and safe lint fixes with:

.. code-block:: console

   ruff format src tests tools docs/conf.py
   ruff check --fix src tests tools docs/conf.py

The committed type-check baseline records known diagnostics exactly. If a
change removes an existing diagnostic, regenerate it with
``python tools/typecheck_closure.py --write`` and review the resulting JSON
diff. Do not add a new diagnostic or an inline suppression in place of fixing
a regression.

Change checklist
----------------

Before opening a pull request:

#. Add or update focused tests for changed behavior.
#. Update the user guide for public behavior or the developer guide for an
   extension contract.
#. Run the relevant unit tests and documentation doctests.
#. Run formatting, linting, and type checking.
#. Keep generated files synchronized with their owning tool and review their
   diffs rather than editing generated output by hand.

Testing Singular export
-----------------------

When Singular is on ``PATH``, the normal unit suite executes generated
programs and verifies that Singular accepts them. Otherwise the integration is
skipped. CI has a dedicated job that installs Singular.

Benchmarking batch evaluation
-----------------------------

Compare the scalar-loop reference with the one-traversal backend using:

.. code-block:: console

   PYTHONPATH=src python tools/benchmark_batch.py --batch-size 32

The benchmark verifies equality before reporting timings. Timings are not CI
assertions because shared runners are noisy.
