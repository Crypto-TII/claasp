"""Compatibility exports retain the package's exact public API identities."""
import claasp.diagrams as public
import claasp.cipher_modules.diagram as implementation


def test_explicit_compatibility_exports_match_package():
    assert public.__all__ == implementation.__all__
    assert len(public.__all__) == len(set(public.__all__))
    for name in public.__all__:
        assert getattr(public, name) is getattr(implementation, name)
    namespace = {}
    exec('from claasp.diagrams import *', namespace)
    assert set(namespace) - {'__builtins__'} == set(public.__all__)
    assert public.Diagrams.__module__ == 'claasp.cipher_modules.diagram.facade'
