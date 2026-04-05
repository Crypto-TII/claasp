"""
Numba CUDA kernel code generation utilities.

Architecture: byte-array based state representation.
Each cipher variable occupies a contiguous region in a local uint8 array.
Bit positions in input_bit_positions are indices INTO the source variable.
"""


def determine_word_size(cipher):
    for component in cipher.get_all_components():
        if component.type == "word_operation":
            return component.output_bit_size
    return 8


def analyze_cipher_state(cipher):
    """
    Assign contiguous byte regions to each cipher variable.
    Returns layout: {name -> (start_byte, num_bytes)}, total_bytes
    """
    layout = {}
    offset = 0
    for i, name in enumerate(cipher.inputs):
        n = cipher.inputs_bit_size[i] // 8
        layout[name] = (offset, n)
        offset += n
    for comp in cipher.get_all_components():
        n = max(1, comp.output_bit_size // 8)
        layout[comp.id] = (offset, n)
        offset += n
    return layout, offset


def generate_device_helpers_code(mode="differential"):
    lines = [
        "# ---- Device helpers ----",
        "@cuda.jit(device=True, inline=True)",
        "def ror8(x, r):",
        "    r = r & 7",
        "    return uint8(((x >> r) | (x << (8 - r))) & 0xFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def rol8(x, r):",
        "    r = r & 7",
        "    return uint8(((x << r) | (x >> (8 - r))) & 0xFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def ror32(x, r):",
        "    r = r & 31",
        "    return uint32(((x >> r) | (x << (32 - r))) & 0xFFFFFFFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def rol32(x, r):",
        "    r = r & 31",
        "    return uint32(((x << r) | (x >> (32 - r))) & 0xFFFFFFFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def ror64(x, r):",
        "    r = r & 63",
        "    return uint64(((x >> r) | (x << (64 - r))) & 0xFFFFFFFFFFFFFFFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def rol64(x, r):",
        "    r = r & 63",
        "    return uint64(((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def ror16(x, r):",
        "    r = r & 15",
        "    return uint16(((x >> r) | (x << (16 - r))) & 0xFFFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def rol16(x, r):",
        "    r = r & 15",
        "    return uint16(((x << r) | (x >> (16 - r))) & 0xFFFF)",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def xorshift32(state):",
        "    state = uint32(state)",
        "    state ^= state << uint32(13)",
        "    state ^= state >> uint32(17)",
        "    state ^= state << uint32(5)",
        "    return state",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def xorshift64(state):",
        "    state = uint64(state)",
        "    state ^= state << uint64(13)",
        "    state ^= state >> uint64(7)",
        "    state ^= state << uint64(17)",
        "    return state",
        "",
        "@cuda.jit(device=True, inline=True)",
        "def gf_mul(a, b, poly):",
        "    p = uint8(0)",
        "    for _ in range(8):",
        "        if b & uint8(1):",
        "            p ^= a",
        "        hi = a & uint8(0x80)",
        "        a = uint8((a << uint8(1)) & uint8(0xFF))",
        "        if hi:",
        "            a ^= uint8(poly & 0xFF)",
        "        b >>= uint8(1)",
        "    return p",
        "",
    ]
    if mode == "differential_linear":
        lines.extend([
            "@cuda.jit(device=True, inline=True)",
            "def popcount64(x):",
            "    count = uint64(0)",
            "    while x:",
            "        count += uint64(x & uint64(1))",
            "        x >>= uint64(1)",
            "    return count",
            "",
        ])
    return lines


def _resolve_numba_input_names(cipher):
    input_sizes = {name: cipher.inputs_bit_size[i] for i, name in enumerate(cipher.inputs)}
    plaintext_name = None
    key_name = None
    for name in cipher.inputs:
        if name in ("plaintext", "message", "state"):
            plaintext_name = name
        elif name == "key":
            key_name = name
    if plaintext_name is None and cipher.inputs:
        plaintext_name = cipher.inputs[0]
    return input_sizes, plaintext_name, key_name


def _is_consecutive(bits):
    return bits == list(range(bits[0], bits[0] + len(bits))) if bits else True


def supports_word_fast_path(cipher):
    input_sizes, plaintext_name, key_name = _resolve_numba_input_names(cipher)
    if plaintext_name is None:
        return False

    word_size = determine_word_size(cipher)
    block_size = input_sizes[plaintext_name]
    key_size = input_sizes[key_name] if key_name is not None else 0

    if word_size not in (16, 32, 64):
        return False
    if block_size <= 0 or block_size > 64 or (block_size % word_size) != 0:
        return False
    if key_size > 64 or (key_size % word_size) != 0:
        return False

    allowed_component_types = {"word_operation", "constant", "intermediate_output", "cipher_output"}
    allowed_word_ops = {"ROTATE", "MODADD", "XOR"}

    for component in cipher.get_all_components():
        if component.type not in allowed_component_types:
            return False

        if component.type == "word_operation":
            if component.output_bit_size != word_size:
                return False
            if component.description[0] not in allowed_word_ops:
                return False
            if any((len(bits) != word_size) or (not _is_consecutive(bits)) for bits in component.input_bit_positions):
                return False
        elif component.type == "constant":
            if component.output_bit_size != word_size:
                return False
        elif component.type == "intermediate_output":
            if component.output_bit_size % word_size != 0:
                return False
            if any((len(bits) % word_size != 0) or (not _is_consecutive(bits)) for bits in component.input_bit_positions if bits):
                return False
        elif component.type == "cipher_output":
            if component.output_bit_size != block_size:
                return False
            if len(component.input_id_links) != block_size // word_size:
                return False
            if any((len(bits) != word_size) or (not _is_consecutive(bits)) for bits in component.input_bit_positions):
                return False

    return True


def _word_type_name(word_size):
    if word_size == 16:
        return "uint16"
    if word_size == 32:
        return "uint32"
    return "uint64"


def _word_mask_hex(word_size):
    if word_size == 64:
        return "0xFFFFFFFFFFFFFFFF"
    return hex((1 << word_size) - 1)


def _extract_word_expr(source_name, total_bits, bit_positions, word_size, cast_type, mask_hex):
    if not bit_positions:
        return f"{cast_type}(0)"
    shift = total_bits - len(bit_positions) - bit_positions[0]
    if shift < 0:
        raise ValueError(f"Unsupported bit positions {bit_positions} for {source_name}")
    return f"{cast_type}((uint64({source_name}) >> uint64({shift})) & uint64({mask_hex}))"


def _get_word_fast_input_expr(component, input_idx, var_names, var_sizes, input_sizes,
                              plaintext_name, key_name, word_size, cast_type, mask_hex):
    input_id = component.input_id_links[input_idx]
    bit_positions = component.input_bit_positions[input_idx]

    if input_id in var_names:
        if len(bit_positions) == var_sizes[input_id] and bit_positions[0] == 0:
            return var_names[input_id]
        return _extract_word_expr(var_names[input_id], var_sizes[input_id], bit_positions, word_size, cast_type, mask_hex)

    if input_id == plaintext_name:
        return _extract_word_expr("plaintext", input_sizes[input_id], bit_positions, word_size, cast_type, mask_hex)

    if input_id == key_name:
        return _extract_word_expr("key", input_sizes[input_id], bit_positions, word_size, cast_type, mask_hex)

    raise ValueError(f"Unsupported fast-path input {input_id} for component {component.id}")


def generate_word_fast_cipher_evaluator_code(cipher, word_size, block_size, key_size):
    input_sizes, plaintext_name, key_name = _resolve_numba_input_names(cipher)
    cast_type = _word_type_name(word_size)
    mask_hex = _word_mask_hex(word_size)
    rotate_right = {16: "ror16", 32: "ror32", 64: "ror64"}[word_size]
    rotate_left = {16: "rol16", 32: "rol32", 64: "rol64"}[word_size]
    n_output_words = block_size // word_size

    lines = [
        "@cuda.jit(device=True, inline=True)",
        "def evaluate_cipher(plaintext, key):",
        "    plaintext = uint64(plaintext)",
        "    key = uint64(key)",
    ]
    var_names = {}
    var_sizes = {}

    for component in cipher.get_all_components():
        cid = component.id.replace("-", "_").replace(".", "_")
        if component.type == "constant":
            val_str = component.description[0]
            val = int(val_str, 16) if isinstance(val_str, str) and val_str.startswith("0x") else int(val_str)
            lines.append(f"    {cid} = {cast_type}({val})")
            var_names[component.id] = cid
            var_sizes[component.id] = component.output_bit_size
        elif component.type == "word_operation":
            op = component.description[0]
            if op == "ROTATE":
                amt = int(component.description[1])
                inp = _get_word_fast_input_expr(component, 0, var_names, var_sizes, input_sizes,
                                                plaintext_name, key_name, word_size, cast_type, mask_hex)
                helper = rotate_right if amt > 0 else rotate_left
                rot_amt = abs(amt)
                lines.append(f"    {cid} = {cast_type}({helper}({inp}, {cast_type}({rot_amt})))")
            elif op == "MODADD":
                inp0 = _get_word_fast_input_expr(component, 0, var_names, var_sizes, input_sizes,
                                                 plaintext_name, key_name, word_size, cast_type, mask_hex)
                inp1 = _get_word_fast_input_expr(component, 1, var_names, var_sizes, input_sizes,
                                                 plaintext_name, key_name, word_size, cast_type, mask_hex)
                lines.append(f"    {cid} = {cast_type}((uint64({inp0}) + uint64({inp1})) & uint64({mask_hex}))")
            elif op == "XOR":
                inp0 = _get_word_fast_input_expr(component, 0, var_names, var_sizes, input_sizes,
                                                 plaintext_name, key_name, word_size, cast_type, mask_hex)
                inp1 = _get_word_fast_input_expr(component, 1, var_names, var_sizes, input_sizes,
                                                 plaintext_name, key_name, word_size, cast_type, mask_hex)
                lines.append(f"    {cid} = {cast_type}({inp0} ^ {inp1})")
            else:
                raise ValueError(f"Unsupported fast-path operation {op}")
            var_names[component.id] = cid
            var_sizes[component.id] = component.output_bit_size
        elif component.type == "intermediate_output":
            # Fast path ignores stored intermediate outputs; Speck does not feed them back.
            continue
        elif component.type == "cipher_output":
            parts = []
            for i in range(n_output_words):
                inp = _get_word_fast_input_expr(component, i, var_names, var_sizes, input_sizes,
                                                plaintext_name, key_name, word_size, cast_type, mask_hex)
                shift = (n_output_words - 1 - i) * word_size
                if shift > 0:
                    parts.append(f"(uint64({inp}) << uint64({shift}))")
                else:
                    parts.append(f"uint64({inp})")
            lines.append(f"    cipher_output = {' | '.join(parts)}")
        else:
            raise ValueError(f"Unsupported fast-path component type {component.type}")

    lines.append("    return cipher_output")
    lines.append("")
    return lines


def generate_word_fast_kernel_code(mode, block_size):
    block_mask = "0xFFFFFFFFFFFFFFFF" if block_size == 64 else hex((1 << block_size) - 1)
    if block_size <= 32:
        rng_init = "        state = xorshift32(uint32(i + 1) ^ uint32(seed))"
    else:
        rng_init = "        state = xorshift64(uint64(i + 1) ^ uint64(seed))"

    if mode == "differential":
        return [
            "@cuda.jit",
            "def differential_kernel(counter, input_diff, output_diff, num_samples, key_bytes, seed):",
            "    idx = cuda.grid(1)",
            "    stride = cuda.gridsize(1)",
            "    key = uint64(0)",
            "    for j in range(key_bytes.shape[0]):",
            "        key = (key << uint64(8)) | uint64(key_bytes[j])",
            "    for i in range(idx, num_samples, stride):",
            rng_init,
            f"        plaintext1 = uint64(state) & uint64({block_mask})",
            "        plaintext2 = plaintext1 ^ input_diff",
            "        ciphertext1 = evaluate_cipher(plaintext1, key)",
            "        ciphertext2 = evaluate_cipher(plaintext2, key)",
            "        if (ciphertext1 ^ ciphertext2) == output_diff:",
            "            cuda.atomic.add(counter, 0, 1)",
        ]

    return [
        "@cuda.jit",
        "def differential_linear_kernel(counter, input_diff, output_mask, num_samples, key_bytes, seed):",
        "    idx = cuda.grid(1)",
        "    stride = cuda.gridsize(1)",
        "    key = uint64(0)",
        "    for j in range(key_bytes.shape[0]):",
        "        key = (key << uint64(8)) | uint64(key_bytes[j])",
        "    for i in range(idx, num_samples, stride):",
        rng_init,
        f"        plaintext1 = uint64(state) & uint64({block_mask})",
        "        plaintext2 = plaintext1 ^ input_diff",
        "        ciphertext1 = evaluate_cipher(plaintext1, key)",
        "        ciphertext2 = evaluate_cipher(plaintext2, key)",
        "        masked = (ciphertext1 ^ ciphertext2) & output_mask",
        "        if (popcount64(masked) & uint64(1)) == uint64(0):",
        "            cuda.atomic.add(counter, 0, 1)",
    ]


# ---------------------------------------------------------------------------
# Core helper: extract a contiguous slice of bits from a source variable
# into output bytes, given bit_positions (indices into the source variable).
# bit_positions must be consecutive and byte-aligned for byte-level ops.
# ---------------------------------------------------------------------------

def _src_byte_offset(bit_positions):
    """First byte index within the source variable."""
    return bit_positions[0] // 8


def _collect_input_as_bytes(component, layout):
    """
    Per output byte, collect ALL absolute state byte indices that contribute.

    Uses the same logic as prepare_input_byte_based_vectorized_python_code_string
    from code_generator to correctly resolve real_bits and real_inputs.
    This handles all cases: simple XOR, N-operand XOR, AES MixColumns-style.
    """
    from claasp.cipher_modules.code_generator import (
        prepare_input_byte_based_vectorized_python_code_string,
        get_number_of_inputs
    )
    from claasp.cipher_modules.generic_functions_vectorized_byte import (
        get_number_of_bytes_needed_for_bit_size
    )

    out_bits = component.output_bit_size
    out_n = max(1, out_bits // 8)
    contributions = [[] for _ in range(out_n)]

    if component.type == "constant":
        return contributions

    # Build output_bit_sizes needed by prepare_input_...
    # We need the bit size of each input variable
    # We can get this from layout: n_bytes * 8
    actual_input_sizes = {}
    for src_id in component.input_id_links:
        if src_id in layout:
            actual_input_sizes[src_id] = layout[src_id][1] * 8
        else:
            actual_input_sizes[src_id] = 0

    # Use prepare_input_byte_based_vectorized_python_code_string logic directly
    # Replicate the key parts: compute real_inputs and real_bits
    number_of_inputs = get_number_of_inputs(component)
    if number_of_inputs is None:
        return contributions

    input_bit_size = component.input_bit_size
    bits = component.input_bit_positions
    bits_per_input = input_bit_size // number_of_inputs
    words_per_input = get_number_of_bytes_needed_for_bit_size(bits_per_input)

    real_inputs = [[] for _ in range(number_of_inputs)]
    real_bits   = [[] for _ in range(number_of_inputs)]
    bits_read = 0
    inputs_read = 0
    cpt_inputs = 0
    pos_in_input = 0

    while inputs_read < number_of_inputs:
        needed_bits = bits_per_input - bits_read
        remaining_bits = len(bits[cpt_inputs]) - pos_in_input
        if remaining_bits == needed_bits:
            real_inputs[inputs_read].append(cpt_inputs)
            real_bits[inputs_read].append(bits[cpt_inputs][pos_in_input:])
            inputs_read += 1
            cpt_inputs += 1
            bits_read = 0
            pos_in_input = 0
        elif remaining_bits > needed_bits:
            real_inputs[inputs_read].append(cpt_inputs)
            real_bits[inputs_read].append(bits[cpt_inputs][pos_in_input:pos_in_input + needed_bits])
            inputs_read += 1
            bits_read = 0
            pos_in_input += needed_bits
        else:
            real_inputs[inputs_read].append(cpt_inputs)
            real_bits[inputs_read].append(bits[cpt_inputs][pos_in_input:])
            bits_read += len(bits[cpt_inputs][pos_in_input:])
            cpt_inputs += 1
            pos_in_input = 0

    # Now map real_inputs/real_bits to output bytes
    # Each of the number_of_inputs operands maps to out_n bytes
    # For operand i: real_bits[i] tells which source bits -> output byte i//out_n ... 
    # Actually each operand contributes to ALL out_n output bytes
    # real_bits[i] is a list of bit-lists from different source links
    # Together they form bits_per_input bits -> words_per_input bytes -> out_byte 0..words_per_input-1
    
    for operand_idx in range(number_of_inputs):
        # Collect all (src_id, bits0, abs_src_byte) for this operand in order
        op_chunks = []
        for link_pos, src_link_idx in enumerate(real_inputs[operand_idx]):
            src_id = component.input_id_links[src_link_idx]
            src_bits_list = real_bits[operand_idx][link_pos]
            src_start = layout[src_id][0] if src_id in layout else None
            for i in range(0, len(src_bits_list), 8):
                chunk = src_bits_list[i:i+8]
                if len(chunk) < 8:
                    continue
                bits0 = chunk[0]
                abs_src = (src_start + bits0 // 8) if src_start is not None else None
                op_chunks.append((bits0, abs_src))

        # Compute n_groups from distinct bits[0] values
        seen_bits0 = []
        for bits0, _ in op_chunks:
            if bits0 not in seen_bits0:
                seen_bits0.append(bits0)
        n_groups = len(seen_bits0)
        group_size = len(op_chunks) // n_groups if n_groups > 0 else 1

        # Assign output bytes using transposed (column-major) indexing:
        # out_byte = within_group_pos * n_groups + group_idx
        # This handles AES ShiftRows column-major structure correctly.
        # For simple operands (n_groups=1 or group_size=1), this degenerates
        # to sequential assignment.
        # Detect column-major vs sequential by checking source link sizes.
        # If all links contributing to this operand have len=8 (1 byte each),
        # they represent individual bytes from different sources -> col-major.
        # If some links have len>8 (multi-byte), they are full words -> sequential.
        # Check the size of links in real_inputs[operand_idx]
        max_link_bits = 0
        for lp, sli in enumerate(real_inputs[operand_idx]):
            max_link_bits = max(max_link_bits, len(real_bits[operand_idx][lp]))
        use_transpose = (max_link_bits <= 8) and group_size > 1

        group_counter = {}
        seq_cursor = 0
        for bits0, abs_src in op_chunks:
            g = seen_bits0.index(bits0)
            p = group_counter.get(bits0, 0)
            group_counter[bits0] = p + 1
            if use_transpose:
                out_byte_idx = (g * group_size + p) % out_n
            else:
                out_byte_idx = seq_cursor % out_n
            seq_cursor += 1
            if abs_src is not None:
                contributions[out_byte_idx].append(abs_src)
    return contributions


def generate_component_code(component, layout, word_size, block_size, key_size):
    code = []
    out_start, out_n = layout[component.id]
    out_bits = component.output_bit_size

    if component.type == "constant":
        val_str = component.description[0]
        val = int(val_str, 16) if isinstance(val_str, str) and val_str.startswith("0x") else int(val_str)
        code.append(f"    # constant {component.id}")
        for i in range(out_n):
            bv = (val >> (8 * (out_n - 1 - i))) & 0xFF
            code.append(f"    state[{out_start + i}] = uint8({bv})")

    elif component.type == "word_operation":
        op = component.description[0]
        code.extend(_gen_word_op(component, layout, word_size, out_start, out_n, out_bits, op))

    elif component.type == "sbox":
        code.extend(_gen_sbox(component, layout, out_start))

    elif component.type == "mix_column":
        code.extend(_gen_mix_column(component, layout, out_start, out_n))

    elif component.type == "linear_layer":
        code.extend(_gen_linear_layer(component, layout, out_start, out_bits))

    elif component.type in ("intermediate_output", "cipher_output"):
        code.extend(_gen_copy(component, layout, out_start, out_n))

    else:
        code.append(f"    # UNSUPPORTED: {component.type} {component.id}")

    return code


# ---------------------------------------------------------------------------
# Word operations
# ---------------------------------------------------------------------------

def _gen_word_op(component, layout, word_size, out_start, out_n, out_bits, op):
    if op == "XOR":
        return _gen_xor(component, layout, out_start, out_n)
    elif op == "AND":
        return _gen_bitwise(component, layout, out_start, out_n, "&")
    elif op == "OR":
        return _gen_bitwise(component, layout, out_start, out_n, "|")
    elif op == "NOT":
        return _gen_not(component, layout, out_start, out_n)
    elif op == "MODADD":
        return _gen_modadd(component, layout, out_start, out_n, out_bits)
    elif op == "ROTATE":
        return _gen_rotate(component, layout, out_start, out_n, out_bits,
                           component.description[1])
    elif op == "SHIFT":
        return _gen_shift(component, layout, out_start, out_n, out_bits,
                          component.description[1])
    else:
        return [f"    # UNSUPPORTED op: {op}"]


def _gen_xor(component, layout, out_start, out_n):
    """XOR: contributions[out_byte] lists all source bytes to XOR."""
    contributions = _collect_input_as_bytes(component, layout)
    code = []
    for i in range(out_n):
        srcs = contributions[i]
        if not srcs:
            code.append(f"    state[{out_start+i}] = uint8(0)")
        elif len(srcs) == 1:
            code.append(f"    state[{out_start+i}] = state[{srcs[0]}]")
        else:
            expr = " ^ ".join(f"state[{s}]" for s in srcs)
            code.append(f"    state[{out_start+i}] = uint8({expr})")
    return code


def _gen_bitwise(component, layout, out_start, out_n, op_sym):
    contributions = _collect_input_as_bytes(component, layout)
    code = []
    for i in range(out_n):
        srcs = contributions[i]
        if not srcs:
            code.append(f"    state[{out_start+i}] = uint8(0)")
        elif len(srcs) == 1:
            code.append(f"    state[{out_start+i}] = state[{srcs[0]}]")
        else:
            expr = f" {op_sym} ".join(f"state[{s}]" for s in srcs)
            code.append(f"    state[{out_start+i}] = uint8({expr})")
    return code


def _gen_not(component, layout, out_start, out_n):
    src_id = component.input_id_links[0]
    src_start, _ = layout[src_id]
    return [f"    state[{out_start+i}] = uint8(~state[{src_start+i}] & 0xFF)"
            for i in range(out_n)]


def _gen_modadd(component, layout, out_start, out_n, out_bits):
    """Modular addition of two equal-size operands."""
    code = []
    # Get the two source byte sequences
    c = _collect_input_as_bytes(component, layout)
    # Each output byte has exactly 2 sources (one from each operand)
    # But _collect_input_as_bytes may interleave them if operands are same size
    # Safer: directly read the two operands
    src0_id = component.input_id_links[0]
    src0_bits = component.input_bit_positions[0]
    src1_id = component.input_id_links[1]
    src1_bits = component.input_bit_positions[1]
    src0_start, _ = layout[src0_id]
    src1_start, _ = layout[src1_id]
    src0_byte = src0_start + src0_bits[0] // 8
    src1_byte = src1_start + src1_bits[0] // 8

    if out_n == 1:
        code.append(f"    state[{out_start}] = uint8((uint16(state[{src0_byte}]) + uint16(state[{src1_byte}])) & 0xFF)")
    elif out_n == 2:
        code.append(f"    _a16 = uint16(state[{src0_byte}]) << uint16(8) | uint16(state[{src0_byte+1}])")
        code.append(f"    _b16 = uint16(state[{src1_byte}]) << uint16(8) | uint16(state[{src1_byte+1}])")
        code.append(f"    _s16 = uint16((_a16 + _b16) & uint16(0xFFFF))")
        code.append(f"    state[{out_start}]   = uint8((_s16 >> uint16(8)) & uint16(0xFF))")
        code.append(f"    state[{out_start+1}] = uint8(_s16 & uint16(0xFF))")
    elif out_n == 4:
        code.append(f"    _a32 = uint32(state[{src0_byte}])<<uint32(24)|uint32(state[{src0_byte+1}])<<uint32(16)|uint32(state[{src0_byte+2}])<<uint32(8)|uint32(state[{src0_byte+3}])")
        code.append(f"    _b32 = uint32(state[{src1_byte}])<<uint32(24)|uint32(state[{src1_byte+1}])<<uint32(16)|uint32(state[{src1_byte+2}])<<uint32(8)|uint32(state[{src1_byte+3}])")
        code.append(f"    _s32 = uint32((_a32 + _b32) & uint32(0xFFFFFFFF))")
        for i in range(4):
            sh = (3 - i) * 8
            code.append(f"    state[{out_start+i}] = uint8((_s32 >> uint32({sh})) & uint32(0xFF))")
    else:
        code.append(f"    _carry = uint16(0)")
        for i in range(out_n - 1, -1, -1):
            code.append(f"    _carry = uint16(uint16(state[{src0_byte+i}]) + uint16(state[{src1_byte+i}]) + _carry)")
            code.append(f"    state[{out_start+i}] = uint8(_carry & uint16(0xFF))")
            code.append(f"    _carry >>= uint16(8)")
    return code


def _gen_rotate(component, layout, out_start, out_n, out_bits, amt):
    """
    ROTATE: concatenate input bytes (handles multi-input = ShiftRows style),
    then rotate the result.
    """
    code = []
    # Collect ordered input bytes
    input_state_bytes = []
    for src_id, bit_positions in zip(component.input_id_links,
                                     component.input_bit_positions):
        if src_id not in layout:
            continue
        src_start, _ = layout[src_id]
        for i in range(0, len(bit_positions), 8):
            chunk = bit_positions[i:i+8]
            if chunk:
                byte_idx = chunk[0] // 8
                input_state_bytes.append(src_start + byte_idx)

    n = len(input_state_bytes)
    if n == 0:
        return code

    if amt == 0:
        # No rotation, just copy
        for i, sb in enumerate(input_state_bytes[:out_n]):
            code.append(f"    state[{out_start+i}] = state[{sb}]")
        return code

    if out_bits <= 8 and n == 1:
        r = abs(amt) % out_bits
        if amt > 0:
            code.append(f"    state[{out_start}] = ror8(state[{input_state_bytes[0]}], uint8({r}))")
        else:
            code.append(f"    state[{out_start}] = rol8(state[{input_state_bytes[0]}], uint8({r}))")
        return code

    if out_bits <= 16 and n <= 2:
        # Use uint16
        if n == 1:
            code.append(f"    _r16 = uint16(state[{input_state_bytes[0]}])")
        else:
            code.append(f"    _r16 = uint16(state[{input_state_bytes[0]}]) << uint16(8) | uint16(state[{input_state_bytes[1]}])")
        r = abs(amt) % out_bits
        if amt > 0:
            code.append(f"    _r16 = ror16(_r16, uint16({r}))")
        else:
            code.append(f"    _r16 = rol16(_r16, uint16({r}))")
        if out_n == 1:
            code.append(f"    state[{out_start}] = uint8(_r16 & uint16(0xFF))")
        else:
            code.append(f"    state[{out_start}]   = uint8((_r16 >> uint16(8)) & uint16(0xFF))")
            code.append(f"    state[{out_start+1}] = uint8(_r16 & uint16(0xFF))")
        return code

    if out_bits <= 32 and n <= 4:
        # Use uint32
        parts = []
        for i, sb in enumerate(input_state_bytes[:4]):
            sh = (n - 1 - i) * 8
            parts.append(f"uint32(state[{sb}]) << uint32({sh})" if sh > 0 else f"uint32(state[{sb}])")
        code.append(f"    _r32 = uint32({' | '.join(parts)})")
        r = abs(amt) % out_bits
        if amt > 0:
            code.append(f"    _r32 = ror32(_r32, uint32({r}))")
        else:
            code.append(f"    _r32 = rol32(_r32, uint32({r}))")
        for i in range(out_n):
            sh = (out_n - 1 - i) * 8
            if sh > 0:
                code.append(f"    state[{out_start+i}] = uint8((_r32 >> uint32({sh})) & uint32(0xFF))")
            else:
                code.append(f"    state[{out_start+i}] = uint8(_r32 & uint32(0xFF))")
        return code

    # Larger: byte-level rotation
    r_bytes = (abs(amt) // 8) % n
    r_bits  = abs(amt) % 8
    if r_bits == 0:
        if amt > 0:
            rotated = input_state_bytes[-r_bytes:] + input_state_bytes[:-r_bytes]
        else:
            rotated = input_state_bytes[r_bytes:] + input_state_bytes[:r_bytes]
        for i, sb in enumerate(rotated[:out_n]):
            code.append(f"    state[{out_start+i}] = state[{sb}]")
    else:
        # Sub-byte large rotation: copy (approximate, rare case)
        for i, sb in enumerate(input_state_bytes[:out_n]):
            code.append(f"    state[{out_start+i}] = state[{sb}]")
    return code


def _gen_shift(component, layout, out_start, out_n, out_bits, amt):
    code = []
    src_id = component.input_id_links[0]
    src_bits = component.input_bit_positions[0]
    src_start, _ = layout[src_id]
    sb = src_start + src_bits[0] // 8

    if out_bits <= 32:
        parts = [f"uint32(state[{sb+i}]) << uint32({(out_n-1-i)*8})" if (out_n-1-i)*8 > 0
                 else f"uint32(state[{sb+i}])" for i in range(out_n)]
        code.append(f"    _sh32 = uint32({' | '.join(parts)})")
        mask = (1 << out_bits) - 1
        if amt > 0:
            code.append(f"    _sh32 = uint32((_sh32 >> uint32({amt})) & uint32({hex(mask)}))")
        else:
            code.append(f"    _sh32 = uint32((_sh32 << uint32({-amt})) & uint32({hex(mask)}))")
        for i in range(out_n):
            sh = (out_n - 1 - i) * 8
            code.append(f"    state[{out_start+i}] = uint8((_sh32 >> uint32({sh})) & uint32(0xFF))" if sh > 0
                        else f"    state[{out_start+i}] = uint8(_sh32 & uint32(0xFF))")
    else:
        nb = abs(amt) // 8
        if amt > 0:
            for i in range(out_n):
                si = i + nb
                code.append(f"    state[{out_start+i}] = state[{sb+si}]" if si < out_n
                             else f"    state[{out_start+i}] = uint8(0)")
        else:
            for i in range(out_n - 1, -1, -1):
                si = i - nb
                code.append(f"    state[{out_start+i}] = state[{sb+si}]" if si >= 0
                             else f"    state[{out_start+i}] = uint8(0)")
    return code


# ---------------------------------------------------------------------------
# SBOX
# ---------------------------------------------------------------------------

def _gen_sbox(component, layout, out_start):
    sbox = component.description
    sbox_name = "sbox_" + component.id.replace("-","_").replace(".","_")
    table_str = "(" + ",".join(str(v) for v in sbox) + ",)"
    src_id = component.input_id_links[0]
    bit_positions = component.input_bit_positions[0]
    src_start, _ = layout[src_id]
    src_byte = src_start + bit_positions[0] // 8
    return [
        f"    {sbox_name} = {table_str}",
        f"    state[{out_start}] = uint8({sbox_name}[state[{src_byte}]])",
    ]


# ---------------------------------------------------------------------------
# MIX_COLUMN
# ---------------------------------------------------------------------------

def _gen_mix_column(component, layout, out_start, out_n):
    matrix  = component.description[0]
    poly    = component.description[1]
    n_rows  = len(matrix)
    n_cols  = len(matrix[0])
    code = []
    tmp_vars = []
    for ci, (src_id, bit_positions) in enumerate(zip(component.input_id_links,
                                                      component.input_bit_positions)):
        src_start, _ = layout[src_id]
        sb = src_start + bit_positions[0] // 8
        tmp = f"_mc{ci}"
        code.append(f"    {tmp} = uint8(state[{sb}])")
        tmp_vars.append(tmp)
    for row in range(n_rows):
        terms = []
        for col in range(n_cols):
            coeff = matrix[row][col]
            var   = tmp_vars[col] if col < len(tmp_vars) else "uint8(0)"
            if coeff == 0:
                continue
            elif coeff == 1:
                terms.append(var)
            else:
                terms.append(f"gf_mul({var}, uint8({coeff}), uint8({poly & 0xFF}))")
        if terms:
            expr = terms[0]
            for t in terms[1:]:
                expr = f"uint8({expr} ^ {t})"
            code.append(f"    state[{out_start+row}] = {expr}")
        else:
            code.append(f"    state[{out_start+row}] = uint8(0)")
    return code


# ---------------------------------------------------------------------------
# LINEAR_LAYER
# ---------------------------------------------------------------------------

def _gen_linear_layer(component, layout, out_start, out_bits):
    matrix  = component.description
    out_n   = max(1, out_bits // 8)
    src_id  = component.input_id_links[0]
    src_start, _ = layout[src_id]
    code = [f"    state[{out_start+i}] = uint8(0)" for i in range(out_n)]
    for out_bit, row in enumerate(matrix):
        ob    = out_bit // 8
        ob_sh = 7 - (out_bit % 8)
        ones  = [j for j, v in enumerate(row) if v == 1]
        if not ones:
            continue
        parts = []
        for src_bit in ones:
            sb    = src_start + src_bit // 8
            sb_sh = 7 - (src_bit % 8)
            parts.append(f"((state[{sb}] >> uint8({sb_sh})) & uint8(1))")
        xc = parts[0]
        for p in parts[1:]:
            xc = f"({xc} ^ {p})"
        code.append(f"    state[{out_start+ob}] |= uint8(uint8({xc}) << uint8({ob_sh}))")
    return code


# ---------------------------------------------------------------------------
# Copy (intermediate_output / cipher_output)
# ---------------------------------------------------------------------------

def _gen_copy(component, layout, out_start, out_n):
    code = []
    input_bytes = []
    for src_id, bit_positions in zip(component.input_id_links,
                                     component.input_bit_positions):
        if src_id not in layout:
            continue
        src_start, _ = layout[src_id]
        for i in range(0, len(bit_positions), 8):
            chunk = bit_positions[i:i+8]
            if chunk:
                input_bytes.append(src_start + chunk[0] // 8)
    for i, sb in enumerate(input_bytes[:out_n]):
        if out_start + i != sb:
            code.append(f"    state[{out_start+i}] = state[{sb}]")
    return code


# ---------------------------------------------------------------------------
# Top-level generators
# ---------------------------------------------------------------------------

def generate_cipher_evaluator_code(cipher, word_size, block_size, key_size):
    layout, total_bytes = analyze_cipher_state(cipher)
    pt_n   = block_size // 8
    key_n  = key_size   // 8
    # Find correct input names - cipher.inputs order may vary
    pt_name  = None
    key_name = None
    for name in cipher.inputs:
        if name in ("plaintext", "message", "state"):
            pt_name = name
        elif name == "key":
            key_name = name
    if pt_name is None:
        pt_name = cipher.inputs[0]
    if key_name is None and len(cipher.inputs) > 1:
        key_name = cipher.inputs[1]
    pt_start  = layout[pt_name][0]
    key_start = layout[key_name][0] if key_name else 0

    cipher_out_start = cipher_out_n = 0
    for comp in cipher.get_all_components():
        if comp.type == "cipher_output":
            cipher_out_start, cipher_out_n = layout[comp.id]
            break

    lines = [
        "@cuda.jit(device=True)",
        "def evaluate_cipher(pt_bytes, key_bytes, out_bytes):",
        f"    state = cuda.local.array({total_bytes}, dtype=uint8)",
        "    for i in range(len(state)):",
        "        state[i] = uint8(0)",
        "",
        "    # Load plaintext, right-aligned to match evaluate_vectorized integer padding.",
        "    _pt_src_len = pt_bytes.shape[0]",
        f"    _pt_copy_len = {pt_n}",
        "    if _pt_src_len < _pt_copy_len:",
        "        _pt_copy_len = _pt_src_len",
        "    _pt_src_start = _pt_src_len - _pt_copy_len",
        f"    _pt_dst_start = {pt_start + pt_n} - _pt_copy_len",
    ]
    lines.append("    for i in range(_pt_copy_len):")
    lines.append("        state[_pt_dst_start + i] = pt_bytes[_pt_src_start + i]")
    lines.append("    # Load key, right-aligned to match evaluate_vectorized integer padding.")
    lines.append("    _key_src_len = key_bytes.shape[0]")
    lines.append(f"    _key_copy_len = {key_n}")
    lines.append("    if _key_src_len < _key_copy_len:")
    lines.append("        _key_copy_len = _key_src_len")
    lines.append("    _key_src_start = _key_src_len - _key_copy_len")
    lines.append(f"    _key_dst_start = {key_start + key_n} - _key_copy_len")
    lines.append("    for i in range(_key_copy_len):")
    lines.append("        state[_key_dst_start + i] = key_bytes[_key_src_start + i]")
    lines.append("    # Evaluate components")

    for comp in cipher.get_all_components():
        lines.extend(generate_component_code(comp, layout, word_size, block_size, key_size))

    lines.append("    # Write output")
    for i in range(cipher_out_n):
        lines.append(f"    out_bytes[{i}] = state[{cipher_out_start+i}]")
    lines.append("")

    return lines, layout, pt_n, key_n, cipher_out_n


def generate_kernel_code(mode, block_size, pt_n, key_n, out_n):
    if mode == "differential":
        return [
            "@cuda.jit",
            "def differential_kernel(counter, input_diff, output_diff, num_samples, key_bytes, seed):",
            "    idx = cuda.grid(1)",
            "    stride = cuda.gridsize(1)",
            f"    pt1 = cuda.local.array({pt_n}, dtype=uint8)",
            f"    pt2 = cuda.local.array({pt_n}, dtype=uint8)",
            f"    ct1 = cuda.local.array({out_n}, dtype=uint8)",
            f"    ct2 = cuda.local.array({out_n}, dtype=uint8)",
            "    for i in range(idx, num_samples, stride):",
            "        s = xorshift64(uint64(i + 1) ^ uint64(seed))",
            f"        for b in range({pt_n}):",
            f"            pt1[b] = uint8((s >> uint64(({pt_n}-1-b)*8)) & uint64(0xFF))",
            f"            s = xorshift64(s)",
            f"        for b in range({pt_n}):",
            f"            pt2[b] = uint8(pt1[b] ^ uint8((input_diff >> uint64(({pt_n}-1-b)*8)) & uint64(0xFF)))",
            "        evaluate_cipher(pt1, key_bytes, ct1)",
            "        evaluate_cipher(pt2, key_bytes, ct2)",
            "        match = True",
            f"        for b in range({out_n}):",
            f"            if ct1[b] ^ ct2[b] != uint8((output_diff >> uint64(({out_n}-1-b)*8)) & uint64(0xFF)):",
            "                match = False",
            "                break",
            "        if match:",
            "            cuda.atomic.add(counter, 0, 1)",
        ]
    else:  # differential_linear
        return [
            "@cuda.jit",
            "def differential_linear_kernel(counter, input_diff, output_mask, num_samples, key_bytes, seed):",
            "    idx = cuda.grid(1)",
            "    stride = cuda.gridsize(1)",
            f"    pt1 = cuda.local.array({pt_n}, dtype=uint8)",
            f"    pt2 = cuda.local.array({pt_n}, dtype=uint8)",
            f"    ct1 = cuda.local.array({out_n}, dtype=uint8)",
            f"    ct2 = cuda.local.array({out_n}, dtype=uint8)",
            "    for i in range(idx, num_samples, stride):",
            "        s = xorshift64(uint64(i + 1) ^ uint64(seed))",
            f"        for b in range({pt_n}):",
            f"            pt1[b] = uint8((s >> uint64(({pt_n}-1-b)*8)) & uint64(0xFF))",
            f"            s = xorshift64(s)",
            f"        for b in range({pt_n}):",
            f"            pt2[b] = uint8(pt1[b] ^ uint8((input_diff >> uint64(({pt_n}-1-b)*8)) & uint64(0xFF)))",
            "        evaluate_cipher(pt1, key_bytes, ct1)",
            "        evaluate_cipher(pt2, key_bytes, ct2)",
            "        parity = uint8(0)",
            f"        for b in range({out_n}):",
            f"            masked = uint8((ct1[b] ^ ct2[b]) & uint8((output_mask >> uint64(({out_n}-1-b)*8)) & uint64(0xFF)))",
            "            p = uint8(0)",
            "            tmp = masked",
            "            while tmp:",
            "                p ^= uint8(tmp & uint8(1))",
            "                tmp >>= uint8(1)",
            "            parity ^= p",
            "        if parity == uint8(0):",
            "            cuda.atomic.add(counter, 0, 1)",
        ]
