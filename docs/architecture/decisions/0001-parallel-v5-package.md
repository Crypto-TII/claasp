# ADR 0001: Develop v5 as a parallel package

Status: accepted

## Decision

Develop CLAASP v5 on the `claasp-v5` branch as an independently installable
distribution under `next/`, using `claasp_next` as its temporary import name.
The package must not import the legacy `claasp` implementation.

## Rationale

This isolates the new dependency graph and prevents partially migrated code
from relying accidentally on Sage or legacy component behavior. Keeping both
implementations in one repository permits direct differential tests, shared
review, and preservation of project history.

The temporary name is removed before the final major release. CLAASP 5 will
continue to use the public package name `claasp`.

## Consequences

- Packaging and tests for `next/` are independent.
- Some temporary duplication of constants or test data is acceptable.
- Production modules cannot import across the old/new boundary.
- Git history and version tags, rather than compatibility code, preserve v4.
