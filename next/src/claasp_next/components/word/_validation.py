from claasp_next.components.algebraic._validation import require_homogeneous_inputs
from claasp_next.domains import Word


def require_word_inputs(inputs, operation):
    value_type = require_homogeneous_inputs(inputs, operation)
    if not isinstance(value_type.domain, Word):
        raise ValueError(f"{operation} requires the Word domain")
    return value_type
