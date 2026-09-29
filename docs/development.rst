Development and testing
=======================

Worktree layout
---------------

CLAASP 5 is the repository-root release tree: the import package is
``src/claasp``, tests are in ``tests``, and documentation is in ``docs``. The
removed v4 tree is preserved at commit
``1e9326b9f9447045b74fdd163c09af6ffc2bb2f9`` on the local
``v4-maintenance`` branch. The two branches can be checked out simultaneously,
for example as:

.. code-block:: text

   <workspace>/claasp-v4  v4-maintenance
   <workspace>/claasp-v5  claasp-v5

List every active checkout with:

.. code-block:: console

   git worktree list

The maintenance branch is provenance and emergency-maintenance history, not a
second package inside the CLAASP 5 release tree.

Running tests
-------------

From the repository root, run the dependency-free unit suite:

.. code-block:: console

   PYTHONPATH=src pytest -q -c pyproject.toml

Run executable examples embedded in public Python APIs:

.. code-block:: console

   PYTHONPATH=src pytest -q --doctest-modules src/claasp -c pyproject.toml

Run both documentation suites:

.. code-block:: console

   make -C docs doctest

Tests marked ``performance`` assert native wall-clock budgets. The release
matrix runs those assertions on native AMD64. Its ARM64 leg still executes the
same inversion and round-trip fixtures under QEMU, but deselects only the
timing assertions because emulation does not measure native performance.

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

The scope is the release package and its supporting tests, tools, and Sphinx
configuration. It does not rewrite the preserved v4 maintenance branch.

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
claim. From the repository root, inspect mathematical/solver model ownership
with:

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

Final migration audit
---------------------

The generated M11a matrix joins every legacy Python source/test record to its
final disposition and maps every shipped package artifact back to legacy
predecessors or an explicit new-v5 rationale. Regenerate and review both the
machine matrix and human summary with:

.. code-block:: console

   python tools/bidirectional_migration_audit.py --write
   python tools/bidirectional_migration_audit.py --check

The check rejects provisional legacy states, missing destinations, duplicate
identities, stale predecessor names, unregistered package artifacts, and
unjustified new-v5 files. Run it immediately before and after the package/root
rename; the committed JSON, generated summary, and package tree must change
together.

Release-tree closure
--------------------

Validate the promoted root layout, distribution/import identity, v4
preservation record, post-rename M11a counts, and CI integration with:

.. code-block:: console

   python tools/release_tree_closure.py --check

The gate rejects the former nested ``next`` tree, a surviving legacy package,
old ``claasp_next`` references in active release text, missing root artifacts,
or a stale bidirectional audit. The final public repository transfer must keep
the star-bearing source public; private candidate work uses a separately named
staging repository.

Private release candidate
-------------------------

The M11.7 authority records the exact local candidate images and distribution
digests without publishing them. Validate the authority and, while the captured
candidate files are present, their byte identity with:

.. code-block:: console

   python tools/private_release_candidate_closure.py --check
   python tools/private_release_candidate_closure.py --check \
       --candidate-artifacts dist/claasp-5.0.0rc1-py3-none-any.whl \
       dist/claasp-5.0.0rc1.tar.gz

Fresh CI builds are audited structurally with ``--artifacts dist/*`` because
archive timestamps can change their byte digests. The gate rejects unsafe
archive paths, caches, reports, tests, migration authorities, and development
tools in distributions. It also enforces the unpublished boundary: local-only
package staging, private image and documentation staging, no committed secret
values, and the prepared branch policy.

The destination organization has not been created. Applying its branch rules,
provisioning owner-controlled secrets, pushing the private image, and enabling
private documentation previews remain blocked by the occupied organization
handle, unnamed owners, and absent destination permissions. Public PyPI is not
used for staging, and no release artifact may be published before M11.8.

Controlled publication preflight
--------------------------------

The M11.8 preflight separates validation of the transfer plan from permission
to execute it:

.. code-block:: console

   python tools/publication_preflight.py --check-plan
   python tools/publication_preflight.py --ready

``--check-plan`` must pass in ordinary CI. It validates the confirmed
five-repository inventory, the selected MIT release target without pretending
the still-GPL candidate has already been relicensed, the ordered transfer procedure, current
metadata capture, and the invariants that protect the public repository's
stars, forks, history, issues, releases, and redirects. ``--ready`` intentionally
exits with status 2 while the human review, AO work, final CLAASP 4
reconciliation, satellite migrations, or owner-controlled prerequisites remain unresolved.
It must pass before any freeze, transfer, visibility change, registry push, or
public package/documentation release.

The live preflight is refreshed with read-only GitHub API calls. Never put
tokens or secret values in its machine authority. The confirmed initial scope
is ``claasp``, ``claasping_aradi``, ``claasping_ballet``,
``claasping_splight``, and ``peacker/claasp_solvers_benchmarks``; the current
operator has administration on all five. The four legacy-dependent satellite
repositories are intentionally migrated only after manual v5 review and AO
analysis validation. The organization handle and two-owner assignment remain
deferred to the final phase described in
``docs/architecture/v5-review-and-release-plan.md``.

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
