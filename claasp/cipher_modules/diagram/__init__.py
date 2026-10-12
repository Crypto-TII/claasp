"""Generic diagram synthesis, human presentation and typed audit serialization.

Use ``to_ascii`` for the readable manual body, ``to_ascii(annotations=True)``
for exact local human metadata, and ``to_audit_ascii`` for the audit encoding. The implementation lives in this package;
``claasp.diagrams`` remains a supported public import path.
"""
from .api import (validate, validate_native_component, from_cipher, to_cipher, to_records, from_records, layout, to_layered_tikz, state_view, to_ascii, synthesis_report, to_audit_ascii, from_ascii, to_tikz, evaluate_state_values, state_snapshots, state_ascii, state_tikz)

__all__ = ['validate', 'validate_native_component', 'from_cipher', 'to_cipher', 'to_records', 'from_records', 'layout', 'to_layered_tikz', 'state_view', 'to_ascii', 'synthesis_report', 'to_audit_ascii', 'from_ascii', 'to_tikz', 'evaluate_state_values', 'state_snapshots', 'state_ascii', 'state_tikz']
