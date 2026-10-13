"""Compatibility import for :mod:`claasp.cipher_modules.diagram`.

Readable manual body: ``to_ascii``. Exact native import: annotated human
``to_ascii(annotations=True)`` or ``to_audit_ascii``, both with ``from_ascii``. Implementation and API documentation
live under ``claasp.cipher_modules.diagram``.
"""
from claasp.cipher_modules.diagram import (
    Diagrams as Diagrams,
    validate as validate,
    validate_native_component as validate_native_component,
    from_cipher as from_cipher,
    to_cipher as to_cipher,
    to_records as to_records,
    from_records as from_records,
    layout as layout,
    to_layered_tikz as to_layered_tikz,
    state_view as state_view,
    to_ascii as to_ascii,
    synthesis_report as synthesis_report,
    to_audit_ascii as to_audit_ascii,
    from_ascii as from_ascii,
    to_tikz as to_tikz,
    evaluate_state_values as evaluate_state_values,
    state_snapshots as state_snapshots,
    state_ascii as state_ascii,
    state_tikz as state_tikz,
    __all__ as __all__,
)
