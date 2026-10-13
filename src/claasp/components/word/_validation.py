from claasp.components.algebraic._validation import (
    normalize_inputs,
    require_homogeneous_inputs,
)
from claasp.unit_types import Word


def require_word_inputs(inputs, operation):
    inputs = normalize_inputs(tuple(inputs))
    array_type = require_homogeneous_inputs(inputs, operation)
    if not isinstance(array_type.unit_type, Word):
        raise ValueError(f"{operation} requires the Word unit_type")
    return inputs, array_type
