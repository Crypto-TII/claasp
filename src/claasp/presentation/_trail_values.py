"""Width-preserving notation shared by trail presentation adapters."""


def _validate_value_format(value_format):
    if value_format not in ("hex", "binary", "underscore_one"):
        raise ValueError("value_format must be 'hex', 'binary', or 'underscore_one'")


def _format_trail_value(value, width=None, *, value_format="hex", pad_hex=False):
    _validate_value_format(value_format)
    if type(value) is not int or value < 0:
        raise ValueError("trail values must be non-negative integers")
    if width is not None and (type(width) is not int or width < 1 or value >= 1 << width):
        raise ValueError("trail value does not fit its positive bit width")
    width = max(1, value.bit_length()) if width is None else width
    if value_format == "hex":
        digits = (width + 3) // 4 if pad_hex else 1
        return f"0x{value:0{digits}x}"
    bits = f"{value:0{width}b}"
    return "0b" + bits if value_format == "binary" else bits.replace("0", "_")
