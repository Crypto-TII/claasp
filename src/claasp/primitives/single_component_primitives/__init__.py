"""One-component primitive fixtures over the public typed component catalogue."""

from claasp.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

_PUBLIC = CATEGORY_EXPORTS["single_component_primitives"]
__all__ = sorted(_PUBLIC)


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
