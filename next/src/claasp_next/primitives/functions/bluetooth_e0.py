"""Bluetooth E0 typed primitive graph."""

from claasp_next.primitives._catalogue_graph import (
    CatalogueGraphPrimitive, load_catalogue_variant,
)


class BluetoothE0(CatalogueGraphPrimitive):
    """Construct Bluetooth E0 from an audited parameter set."""

    def __init__(self, *args, **parameters) -> None:
        specification = load_catalogue_variant("functions", "bluetooth_e0", args, parameters)
        super().__init__(specification)


__all__ = ["BluetoothE0"]
