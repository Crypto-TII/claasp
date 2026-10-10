"""Backend-independent component descriptions."""

from dataclasses import dataclass

from claasp.graph.array_type import ArrayType
from claasp.graph.port import Port, Selection


@dataclass(frozen=True, slots=True)
class Component:
    """An immutable typed operation in a primitive graph.

    Concrete component families will add their semantic parameters and
    validation. This base class deliberately contains no evaluator or solver
    methods.

    EXAMPLES::

        >>> from claasp import ArrayType
        >>> from claasp.domains import Bit
        >>> component = Component("identity_0", (), ArrayType(Bit(), (1,)))
        >>> component.output.owner_id
        'identity_0'
    """

    component_id: str | None
    inputs: tuple[Selection, ...]
    output_type: ArrayType

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
        if not isinstance(self.output_type, ArrayType):
            raise TypeError("output_type must be an ArrayType")

    @property
    def output(self) -> Port:
        """Return the component output after an identifier is assigned."""

        if self.component_id is None:
            raise ValueError("component has no identifier until it is added to a primitive")
        return Port(self.component_id, self.output_type)
