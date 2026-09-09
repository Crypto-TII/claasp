"""Components that manipulate structure without applying scalar algebra."""

from claasp_next.components.structural.concatenate import Concatenate
from claasp_next.components.structural.constant import Constant
from claasp_next.components.structural.identity import Identity
from claasp_next.components.structural.permutation import Permutation

__all__ = ["Concatenate", "Constant", "Identity", "Permutation"]
