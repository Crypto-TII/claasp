"""Validate explicit stage origins without importing legacy graph machinery."""


def stage_configuration(start_round, round_mode):
    if round_mode not in ("single", "half", "half_half"):
        raise ValueError("round_mode must be single, half, or half_half")
    if not isinstance(start_round, (tuple, list)) or len(start_round) != 2:
        raise ValueError("start_round must contain parity and stage")
    parity, label = start_round
    labels = {
        "top": 0,
        "top_first": 0,
        "top_second": 1,
        "bottom": 2,
        "bottom_first": 2,
        "bottom_second": 3,
    }
    if parity not in ("odd", "even") or label not in labels:
        raise ValueError("invalid start_round parity or stage")
    if round_mode != "half_half" and label not in ("top", "bottom"):
        raise ValueError("individual stages require round_mode=half_half")
    return (4 if parity == "even" else 0) + labels[label], {"single": 4, "half": 2, "half_half": 1}[
        round_mode
    ]
