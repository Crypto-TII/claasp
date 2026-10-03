# Unit-test ownership

The functional unit-test tree mirrors `src/claasp` at both package and module
level.  A source module `src/claasp/<package>/<module>.py` is tested by
`tests/unit/<package>/test_<module>.py`.

When one source module needs more than one focused suite, additional files use
`test_<module>__<topic>.py`.  Package-wide contracts owned by `__init__.py` use
`test_package.py` or `test_package__<topic>.py`.  These forms keep ownership
mechanically discoverable without forcing unrelated cross-module behavior into
an arbitrarily named test file.

`repository/` is the deliberate exception. It contains checks for migration
authorities, generated inventories, CI policy, packaging, release closure, and
other repository-level contracts that are not owned by one runtime package.

When adding a test, choose the narrowest source module that owns its primary
contract. Cross-module end-to-end behavior belongs in `tests/integration`.
The layout test rejects test directories without a source-package counterpart
and filenames without a source-module counterpart.
