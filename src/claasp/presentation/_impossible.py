"""Single-column views of retained forward/backward impossible trails."""

from dataclasses import dataclass
from typing import Any

from claasp.presentation._trail_values import _format_trail_value, _validate_value_format


@dataclass(frozen=True)
class _Row:
    direction: str
    boundary: str
    source: str
    pattern: Any
    contradictions: tuple[int, ...] = ()


def _is_impossible(result):
    from claasp.analysis.composed_search import ImpossibleSearchResult
    from claasp.representations.constraints.sat.trails import (
        AutomaticWordImpossibleSATResult,
        WordImpossibleSATTrail,
        WordwiseImpossibleSATTrail,
    )
    from claasp.semantics.cryptanalysis import ImpossiblePropagationBoundary

    return isinstance(
        result,
        (
            ImpossibleSearchResult,
            AutomaticWordImpossibleSATResult,
            WordImpossibleSATTrail,
            WordwiseImpossibleSATTrail,
            ImpossiblePropagationBoundary,
        ),
    )


def _groups(result, *, details=False):
    from claasp.analysis.composed_search import ImpossibleSearchResult
    from claasp.representations.constraints.sat.trails import AutomaticWordImpossibleSATResult

    if isinstance(result, ImpossibleSearchResult):
        return tuple(
            (
                f"Candidate {i}, middle round {item.middle_round}, {item.representation}",
                item.trail,
                _rows(item.trail, item.middle_round, details=details),
            )
            for i, item in enumerate(result.candidates)
        )
    if isinstance(result, AutomaticWordImpossibleSATResult):
        return (
            ()
            if result.trail is None
            else (
                (
                    f"Middle round {result.middle_round}",
                    result.trail,
                    _rows(result.trail, result.middle_round, details=details),
                ),
            )
        )
    return (
        (
            "Impossible differential trail",
            result,
            _rows(result, getattr(result, "middle_round", None), details=details),
        ),
    )


def _boundary(trail):
    if hasattr(trail, "boundary"):
        return (
            trail.boundary.forward,
            trail.boundary.backward,
            trail.boundary.contradictory_positions,
            False,
        )
    if hasattr(trail, "middle"):
        middle = trail.middle
        forward, backward = getattr(trail, "forward", None), getattr(trail, "backward", None)

        def retained(characteristic, states):
            words = () if characteristic is None else characteristic.output_differences
            return words if tuple(item.kind.value for item in words) == states else states

        return (
            retained(forward, middle.forward_states),
            retained(backward, middle.backward_states),
            middle.contradictory_positions,
            True,
        )
    return trail.forward, trail.backward, trail.contradictory_positions, False


def _rows(trail, middle_round, *, details):
    from claasp.semantics.cryptanalysis import ImpossiblePropagationBoundary

    above, below, positions, wordwise = _boundary(trail)
    forward = None if isinstance(trail, ImpossiblePropagationBoundary) else trail.forward
    backward = None if isinstance(trail, ImpossiblePropagationBoundary) else trail.backward
    inputs = "input_differences" if wordwise else "input_patterns"
    components = "component_differences" if wordwise else "component_patterns"
    rows: list[_Row] = []
    if forward is not None:
        rows.extend(
            _Row("above ↓", "input", name, pattern) for name, pattern in getattr(forward, inputs)
        )
    rows.extend(
        _Row("above ↓", str(number), "round output", pattern)
        for number, pattern in getattr(trail, "forward_rounds", ())
        if number != middle_round
    )
    if details and forward is not None:
        rows.extend(
            _Row("above ↓", "component", name, pattern)
            for name, pattern in getattr(forward, components)
        )
    label = f"{middle_round} (middle)" if middle_round is not None else "middle"
    rows.extend(
        (
            _Row("above ↓", label, "meeting state", above, positions),
            _Row("below ↑", label, "meeting state", below, positions),
        )
    )
    if details and backward is not None:
        rows.extend(
            _Row("below ↑", "component", name, pattern)
            for name, pattern in reversed(getattr(backward, components))
        )
    backward_rounds = getattr(trail, "backward_rounds", ())
    rows.extend(
        _Row("below ↑", str(number), "round output", pattern)
        for number, pattern in backward_rounds
        if number != middle_round
    )
    if backward is not None:
        output = dict(getattr(backward, inputs)).get("output")
        if output is not None:
            if backward_rounds and rows[-1].pattern == output:
                last = rows[-1]
                rows[-1] = _Row(last.direction, last.boundary, "ciphertext", output)
            else:
                rows.append(_Row("below ↑", "output", "ciphertext", output))
    return tuple(rows)


def _values(pattern):
    if hasattr(pattern, "bits"):
        return tuple(float(bit.encoded) for bit in pattern.bits)
    return tuple(float(item.kind.value if hasattr(item, "kind") else item) for item in pattern)


def _pattern(pattern, *, value_format):
    if hasattr(pattern, "bits"):
        bits = str(pattern)
        if value_format == "underscore_one":
            return bits.replace("0", "_")
        if "?" in bits:
            return "0b" + bits
        return _format_trail_value(int(bits, 2), len(bits), value_format=value_format, pad_hex=True)
    words = []
    for item in pattern:
        if isinstance(item, int):
            words.append(("zero", "known", "*", "?")[item])
        elif item.kind.value in (0, 1):
            words.append(
                _format_trail_value(
                    item.value or 0, item.width, value_format=value_format, pad_hex=True
                )
            )
        else:
            words.append("*" if item.kind.value == 2 else "?")
    return "[" + ", ".join(words) + "]"


def _notes(result):
    notes = []
    if hasattr(result, "complete"):
        notes.append(f"Complete: {result.complete}")
    if hasattr(result, "termination"):
        notes.append(f"Termination: {result.termination}")
    if getattr(result, "representation", None) is not None:
        notes.append(f"Truncated model: {result.representation}")
    if getattr(result, "complete", False):
        notes.append("Exhaustion applies only to the selected truncated model.")
    if hasattr(result, "attempted_rounds"):
        notes.append(f"Attempted middle rounds: {result.attempted_rounds}")
    notes.extend(
        (
            "! marks contradictory MSB-first bit/word positions in both middle rows.",
            "? is unknown; * is a nonzero word of unspecified value.",
            "Round labels count original graph boundaries. Below ↑ propagates from ciphertext.",
            "Retained abstract evidence; no whole-primitive probability claim.",
        )
    )
    return tuple(notes)


def _to_terminal(result, *, details=False, value_format="binary", file=None):
    from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

    _validate_value_format(value_format)
    print("Impossible differential trail", file=file)
    for note in _notes(result):
        print(note, file=file)
    groups = _groups(result, details=details)
    if not groups:
        print("No retained witness to display.", file=file)
    for title, trail, rows in groups:
        print(title, file=file)
        columns = tuple(
            TableColumn(key, label)
            for key, label in (
                ("direction", "From"),
                ("boundary", "Boundary"),
                ("source", "Source"),
                ("pattern", "Difference"),
                ("conflict", "Contradiction !"),
            )
        )
        values = tuple(
            TableRow.of(
                row.direction,
                row.boundary,
                row.source,
                _pattern(row.pattern, value_format=value_format),
                "".join(
                    "!" if i in row.contradictions else "."
                    for i in range(len(_values(row.pattern)))
                )
                if row.contradictions
                else "",
            )
            for row in rows
        )
        print(render_terminal_table(Table(columns, values)), file=file)
        if not getattr(trail, "forward_rounds", ()) and not getattr(trail, "backward_rounds", ()):
            print("Intermediate round observations were not retained in this witness.", file=file)
