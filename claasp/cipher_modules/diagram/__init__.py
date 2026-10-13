"""Generic diagram synthesis, human presentation and typed audit serialization.

Use ``to_ascii`` for admitted persistent word views; unsupported shapes require
an explicit legacy choice. ``annotations=True`` preserves the ordinary picture and adds local
native metadata. ``format='human-legacy'`` retains the old exact manual serializer;
``to_audit_ascii`` retains the audit encoding. The implementation lives in this package;
``claasp.diagrams`` remains a supported public import path.
"""
from .api import (validate, validate_native_component, from_cipher, to_cipher, to_records, from_records, layout, to_layered_tikz, state_view, to_ascii, synthesis_report, to_audit_ascii, from_ascii, to_tikz, evaluate_state_values, state_snapshots, state_ascii, state_tikz)

from .facade import Diagrams

__all__ = ['Diagrams', 'validate', 'validate_native_component', 'from_cipher', 'to_cipher', 'to_records', 'from_records', 'layout', 'to_layered_tikz', 'state_view', 'to_ascii', 'synthesis_report', 'to_audit_ascii', 'from_ascii', 'to_tikz', 'evaluate_state_values', 'state_snapshots', 'state_ascii', 'state_tikz']
