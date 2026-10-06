"""Compatibility imports for word-differential SMT trail models."""

from claasp.representations.constraints.smt.trails import (
    WordDifferentialCharacteristic as _WordDifferentialCharacteristic,
)
from claasp.representations.constraints.smt.trails import (
    WordDifferentialEnumeration as _WordDifferentialEnumeration,
)
from claasp.representations.constraints.smt.trails import (
    WordDifferentialSMTModel as _WordDifferentialSMTModel,
)

WordDifferentialCharacteristic = _WordDifferentialCharacteristic
WordDifferentialEnumeration = _WordDifferentialEnumeration
WordDifferentialSMTModel = _WordDifferentialSMTModel
