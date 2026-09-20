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

Formatting and linting
----------------------

Install the exact quality-tool versions and run the check-only commands used
by CI:

.. code-block:: console

   python -m pip install -e '.[quality]'
   ruff format --check src tests tools docs/conf.py
   ruff check src tests tools docs/conf.py
   python tools/typecheck_closure.py --check

Apply the formatter and safe lint fixes locally with:

.. code-block:: console

   ruff format src tests tools docs/conf.py
   ruff check --fix src tests tools docs/conf.py

The scope is intentionally the v5 package and its supporting tests, tools, and
Sphinx configuration. It does not rewrite the legacy v4 tree.

The typing command runs pinned mypy over that same boundary. The committed
machine baseline records every remaining adoption diagnostic by path, line,
column, code, and message; it rejects both new and stale entries and permits no
inline ``type: ignore`` or ``mypy:`` suppression. When a change removes typing
debt, regenerate the authority with ``python tools/typecheck_closure.py
--write`` and review the JSON diff together with the fix. Do not add or move a
diagnostic into the baseline as a substitute for correcting a new regression.

Model migration closure
-----------------------

The exhaustive inventory's filesystem check is not a migration-completion
claim. From ``next/``, inspect remaining mathematical/solver model work with:

.. code-block:: console

   python tools/legacy_inventory.py --model-status
   python tools/legacy_inventory.py --check-model-closure

The first command reports reviewed replacements, unresolved families, and
explicit deferrals without rewriting files. The second exits nonzero while
unreviewed destinations or deferred model requirements remain. Use it before
closing M10.8; a complete inventory alone does not justify that milestone.

Upstream reconciliation
-----------------------

The v5 release branch does not merge the legacy ``develop`` line. Before a
release candidate, fetch it, review every commit after the recorded common
ancestor, and classify each change in
``migration/m11_upstream_reconciliation.json`` as either a behavior port or a
v5 supersession with concrete evidence. Validate the fixed review boundary
with:

.. code-block:: console

   python tools/upstream_reconciliation_closure.py --check

The authority must be extended when ``develop`` advances. Never silently
ignore a new commit or copy a legacy mutable API merely to make histories
look alike. The current review ports the corrected 160-bit Grain v1
initialization core and records why legacy bibliography, mutable CP-cache,
and mutable SAT-search changes are already superseded by v5 contracts.

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
