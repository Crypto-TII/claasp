"""Backend-independent component descriptions."""

from dataclasses import dataclass

from claasp.graph.unit_array import Selection, UnitArray
from claasp.graph.unit_array_type import UnitArrayType


@dataclass(frozen=True, slots=True)
class Component:
    """An immutable typed operation in a primitive graph.

    Concrete component families will add their semantic parameters and
    validation. This base class deliberately contains no evaluator or solver
    methods.

    EXAMPLES::

        >>> from claasp import UnitArrayType
        >>> from claasp.unit_types import Bit
        >>> component = Component("identity_0", (), UnitArrayType(Bit(), (1,)))
        >>> component.output.source_id
        'identity_0'
    """

    component_id: str | None
    inputs: tuple[Selection, ...]
    output_type: UnitArrayType

    def __post_init__(self) -> None:
        if self.component_id is not None:
            if not isinstance(self.component_id, str):
                raise TypeError("component_id must be a string or None")
            if not self.component_id:
                raise ValueError("component_id must not be empty")
        if not isinstance(self.inputs, tuple):
            raise TypeError("inputs must be a tuple")
        if any(not isinstance(component_input, Selection) for component_input in self.inputs):
            raise TypeError("every component input must be a Selection")
        if not isinstance(self.output_type, UnitArrayType):
            raise TypeError("output_type must be an UnitArrayType")

    @property
    def output(self) -> UnitArray:
        """Return the component output after an identifier is assigned."""

        if self.component_id is None:
            raise ValueError("component has no identifier until it is added to a primitive")
        return UnitArray(self.component_id, self.output_type)
