# Unit-test ownership

The functional unit-test tree mirrors `src/claasp`. A test belongs under the
directory of the source package that owns the behavior it verifies. Root-level
tests cover root source modules or the public `claasp` package facade.

`repository/` is the deliberate exception. It contains checks for migration
authorities, generated inventories, CI policy, packaging, release closure, and
other repository-level contracts that are not owned by one runtime package.

Tests may cover several cooperating modules and do not need an artificial
one-file-per-source-file split. When adding a test, choose the narrowest source
package that owns its primary contract. The layout test rejects directories
that do not correspond to a source package and unregistered root-level tests.
