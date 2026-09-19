"""Public finite-domain substitution component descriptions."""

from claasp_next.components.substitution.bit_vector_sbox import BitVectorSBox
from claasp_next.components.substitution.lookup_table import LookupTable
from claasp_next.components.substitution.sbox import SBox

__all__ = ["BitVectorSBox", "LookupTable", "SBox"]
