# Documentation sources

The `.rst` files in this directory are Sphinx source pages. Their reading
order is defined by the two guide entry points rather than by filename:

- `user_guide.rst` contains the user-guide table of contents, beginning with
  Getting started and Core concepts.
- `developer_guide.rst` contains architecture, extension, testing, and API
  documentation for contributors.
- `index.rst` is a compact combined index for local browsing.
- `conf.py` and `Makefile` build and test both guides.

Keeping public page filenames stable preserves documentation URLs and existing
cross-references. Generated HTML and doctest output live under `_build/` and
are not source documentation.

Historical design notes, release plans, and generated audit reports live in
`architecture/`. They are engineering records rather than user-guide pages.
Open review findings that are intentionally split across later pull requests
are tracked in `architecture/v5-follow-up-backlog.md`.

Build and contribution commands are documented in `development.rst`.
