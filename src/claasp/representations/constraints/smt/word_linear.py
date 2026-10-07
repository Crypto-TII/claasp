"""Compatibility imports for word-linear SMT trail models."""

from claasp.representations.constraints.smt.trails import (
    WordLinearCharacteristic as _WordLinearCharacteristic,
)
from claasp.representations.constraints.smt.trails import (
    WordLinearEnumeration as _WordLinearEnumeration,
)
from claasp.representations.constraints.smt.trails import (
    WordLinearSMTModel as _WordLinearSMTModel,
)
from claasp.representations.constraints.smt.trails import (
    _packed as _packed_impl,
)

WordLinearCharacteristic = _WordLinearCharacteristic
WordLinearEnumeration = _WordLinearEnumeration
WordLinearSMTModel = _WordLinearSMTModel
_packed = _packed_impl
