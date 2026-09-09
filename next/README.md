# claasp-next

This directory contains the Sage-independent prototype for CLAASP 5. It is a
separate distribution and must not import the legacy `claasp` package.

Development installation:

```bash
python -m pip install -e '.[dev]'
pytest
```

The v5 branch is commonly checked out in a separate Git worktree. Confirm the
active checkout with `git status` or list all of them with `git worktree list`.

Complete test and documentation commands are in
[`docs/development.rst`](docs/development.rst).

The public import name `claasp_next` is temporary. It will become `claasp`
only during final v5 integration.
