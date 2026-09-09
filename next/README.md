# claasp-next

This directory contains the Sage-independent prototype for CLAASP 5. It is a
separate distribution and must not import the legacy `claasp` package.

Development installation:

```bash
python -m pip install -e '.[dev]'
pytest
```

The public import name `claasp_next` is temporary. It will become `claasp`
only during final v5 integration.
