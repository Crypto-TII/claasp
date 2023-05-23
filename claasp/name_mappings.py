# cipher_type
BLOCK_CIPHER = "block_cipher"
STREAM_CIPHER = "stream_cipher"
TWEAKABLE_BLOCK_CIPHER = "tweakable_block_cipher"
PERMUTATION = "permutation"
HASH_FUNCTION = "hash_function"

# CIPHER INPUTS
INPUT_KEY = "key"
INPUT_PLAINTEXT = "plaintext"
INPUT_INITIALIZATION_VECTOR = "initialization_vector"
INPUT_NONCE = "nonce"
INPUT_MESSAGE = "input_message"
INPUT_STATE = "input_state"
INPUT_BLOCK_COUNT = "input_block_count"
INPUT_TWEAK = "input_tweak"

# component types
CIPHER_INPUT = "cipher_input"
INTERMEDIATE_OUTPUT = "intermediate_output"
CIPHER_OUTPUT = "cipher_output"
CONCATENATE = "concatenate"
PADDING = "padding"
CONSTANT = "constant"
WORD_OPERATION = "word_operation"
MIX_COLUMN = "mix_column"
LINEAR_LAYER = "linear_layer"
SBOX = "sbox"
FSR = "fsr"

# model types
CIPHER = 'cipher'
XOR_DIFFERENTIAL = 'xor_differential'
XOR_LINEAR = 'xor_linear'
DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL = 'deterministic_truncated_xor_differential'
IMPOSSIBLE_XOR_DIFFERENTIAL = 'impossible_xor_differential'
