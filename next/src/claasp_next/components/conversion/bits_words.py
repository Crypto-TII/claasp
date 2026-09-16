"""Explicit MSB-first conversion between bit and word vectors."""

from dataclasses import dataclass

from claasp_next.domains import BinaryExtensionField, Bit, Word
from claasp_next.graph.component import Component
from claasp_next.graph.port import PortLike, as_selection
from claasp_next.graph.value_type import ValueType


@dataclass(frozen=True, slots=True, init=False)
class PackBits(Component):
    """Pack consecutive MSB-first bits into fixed-width words.

    >>> from claasp_next import Bit, Port, ValueType
    >>> from claasp_next.components import PackBits
    >>> PackBits(Port("bits", ValueType(Bit(), (16,))), 8).output_type
    ValueType(domain=Word(width=8), shape=(2,))
    """

    word_width: int

    def __init__(
        self, component_input: PortLike, word_width: int, component_id: str | None = None,
        *, output_domain: BinaryExtensionField | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        if not isinstance(component_input.value_type.domain, Bit):
            raise ValueError("PackBits input must use the Bit domain")
        if not isinstance(word_width, int) or isinstance(word_width, bool) or word_width <= 0:
            raise ValueError("word_width must be a positive integer")
        bit_count = component_input.value_type.unit_count
        if bit_count % word_width:
            raise ValueError("input bit count must be a multiple of word_width")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        if output_domain is not None and output_domain.degree != word_width:
            raise ValueError("binary-field degree must equal word_width")
        domain = output_domain if output_domain is not None else Word(word_width)
        object.__setattr__(self, "output_type", ValueType(domain, (bit_count // word_width,)))
        object.__setattr__(self, "word_width", word_width)
        Component.__post_init__(self)


@dataclass(frozen=True, slots=True, init=False)
class UnpackBits(Component):
    """Expand fixed-width words into consecutive MSB-first bits."""

    word_width: int

    def __init__(self, component_input: PortLike, component_id: str | None = None) -> None:
        component_input = as_selection(component_input)
        domain = component_input.value_type.domain
        if not isinstance(domain, (Word, BinaryExtensionField)):
            raise ValueError("UnpackBits input must use a Word or binary-field domain")
        word_count = component_input.value_type.unit_count
        word_width = domain.width if isinstance(domain, Word) else domain.degree
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", ValueType(Bit(), (word_count * word_width,)))
        object.__setattr__(self, "word_width", word_width)
        Component.__post_init__(self)
