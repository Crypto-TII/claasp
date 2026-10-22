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

Stable design explanations live in `architecture/`. Completed migration
plans, generated audits, and temporary review notes are kept in their original
pull requests or release records rather than in the published documentation.

Build and contribution commands are documented in `development.rst`.

`examples/basic_avalanche.py` and `examples/avalanche.py` accompany the basic
and advanced avalanche pages. Inline Matplotlib Sphinx directives execute the displayed commands in a
shared context, retaining each analysis result for all of its plot views. The
basic terminal output is generated during the build and included next to its
command. `tests/examples/test_avalanche_example.py` exercises the companion
script with small, seeded inputs in the presentation CI job. Run it headlessly
with `MPLBACKEND=Agg python -m pytest tests/examples/test_avalanche_example.py`.
