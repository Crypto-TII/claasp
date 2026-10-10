from claasp.components.algebraic._validation import (
    normalize_inputs,
    require_homogeneous_inputs,
)
from claasp.domains import Word


def require_word_inputs(inputs, operation):
    inputs = normalize_inputs(tuple(inputs))
    array_type = require_homogeneous_inputs(inputs, operation)
    if not isinstance(array_type.domain, Word):
        raise ValueError(f"{operation} requires the Word domain")
    return inputs, array_type
