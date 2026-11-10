"""Type-specific views of retained search evidence; no search is performed here."""

from dataclasses import dataclass
from itertools import accumulate
from math import log2
from typing import Any


@dataclass(frozen=True)
class _Panel:
    title: str
    labels: tuple[str, ...]
    series: tuple[tuple[str, tuple[float, ...]], ...]
    ylabel: str
    xlabel: str = "Component transition"
    states: tuple[str, ...] = ()


@dataclass(frozen=True)
class _View:
    title: str
    notes: tuple[str, ...] = ()
    panels: tuple[_Panel, ...] = ()


def _weights(weights, labels, title, *, xlabel="Component transition"):
    values = tuple(float(value) for value in weights)
    return _Panel(
        title,
        tuple(labels),
        (("relative weight", values), ("cumulative weight", tuple(accumulate(values)))),
        "Weight (bits)",
        xlabel,
    )


def _bars(title, names, values, ylabel):
    return _Panel(
        title, tuple(names), ((ylabel, tuple(float(v) for v in values)),), ylabel, "Evidence"
    )


def _patterns(patterns, title):
    # Unknown is a category, never silently converted into an active bit.
    return tuple(
        _Panel(
            f"{title}: {name}",
            tuple(map(str, range(len(pattern.bits)))),
            (("state", tuple(float(bit.encoded) for bit in pattern.bits)),),
            "Truncated difference",
            "Bit position (MSB first)",
            ("0", "1", "?"),
        )
        for name, pattern in patterns
    )


def _word_patterns(patterns, title):
    return tuple(
        _Panel(
            f"{title}: {name}",
            tuple(map(str, range(len(words)))),
            (("state", tuple(float(word.kind.value) for word in words)),),
            "Word activity category",
            "Word position",
            ("zero", "known", "nonzero", "unknown"),
        )
        for name, words in patterns
    )


def _view(result: Any) -> _View:
    notes: tuple[str, ...]
    panels: tuple[_Panel, ...]
    # Imports stay within the presentation boundary and are reached only on demand.
    from claasp.analysis.advanced_trails import CPCharacteristicResult, TruncatedPropagationResult
    from claasp.analysis.boomerang_search import BoomerangSearchResult
    from claasp.analysis.composed_search import (
        ImpossibleSearchResult,
        XorDifferentialLinearSearchResult,
    )
    from claasp.analysis.continuous_differential import ContinuousCorrelationResult
    from claasp.analysis.minimax_differential import MinimaxDifferentialResult
    from claasp.analysis.quasidifferential import (
        FixedKeyProbabilityResult,
        QuasidifferentialEnumeration,
        QuasidifferentialTrail,
    )
    from claasp.analysis.wordwise_activity import ActiveSBoxResult
    from claasp.representations.constraints.sat.boomerang import ARXBoomerangTrail
    from claasp.representations.constraints.sat.partitioned_differential import (
        PartitionedDifferentialTrail,
    )
    from claasp.representations.constraints.sat.trails import (
        AutomaticWordImpossibleSATResult,
        SharedDifferencePairedSATTrail,
        SharedDifferencePairedXorDifferentialLinearSATTrail,
        SpeckSemiDeterministicTruncatedTrail,
        WordDeterministicTruncatedCharacteristic,
        WordDeterministicTruncatedEnumeration,
        WordDeterministicXorDifferentialLinearSATTrail,
        WordImpossibleSATTrail,
        WordSemiDeterministicXorDifferentialLinearSATTrail,
        WordwiseDeterministicTruncatedCharacteristic,
        WordwiseImpossibleSATTrail,
    )
    from claasp.representations.constraints.smt.word_xor_differential import (
        WordXorDifferentialCharacteristic,
        WordXorDifferentialEnumeration,
    )
    from claasp.representations.constraints.smt.word_xor_linear import (
        WordXorLinearCharacteristic,
        WordXorLinearEnumeration,
    )
    from claasp.semantics.cryptanalysis import (
        ImpossiblePropagationBoundary,
        ProbabilisticTruncatedTrail,
    )

    if isinstance(result, (WordXorDifferentialCharacteristic, WordXorLinearCharacteristic)):
        linear = isinstance(result, WordXorLinearCharacteristic)
        return _View(
            "XOR-linear characteristic" if linear else "XOR-differential characteristic",
            (
                "Component characteristic; no whole-primitive probability or hull claim.",
                f"total weight: {result.total_weight:g}",
                *(
                    (f"correlation sign: {result.sign}",)
                    if isinstance(result, WordXorLinearCharacteristic)
                    else ()
                ),
            ),
            (
                _weights(
                    (step.transition.weight for step in result.steps),
                    (step.component_id for step in result.steps),
                    "Absolute correlation weights" if linear else "Probability weights",
                ),
            ),
        )
    if isinstance(
        result,
        (
            WordXorDifferentialEnumeration,
            WordXorLinearEnumeration,
            WordDeterministicTruncatedEnumeration,
            QuasidifferentialEnumeration,
        ),
    ):
        notes = (f"complete: {result.complete}", f"retained trails: {len(result.trails)}")
        if not result.complete:
            notes += ("Incomplete enumeration; retained trails are not an exhaustive set.",)
        if isinstance(result, WordDeterministicTruncatedEnumeration):
            panels = tuple(
                panel
                for i, trail in enumerate(result.trails)
                for panel in _prefix(_view(trail).panels, f"Trail {i}")
            )
        else:
            signed = isinstance(result, QuasidifferentialEnumeration)
            panels = (
                (
                    _bars(
                        "Retained signed coefficients"
                        if signed
                        else "Retained characteristic weights",
                        map(str, range(len(result.trails))),
                        (
                            trail.coefficient
                            if isinstance(trail, QuasidifferentialTrail)
                            else trail.total_weight
                            for trail in result.trails
                        ),
                        "Signed coefficient" if signed else "Weight (bits)",
                    ),
                )
                if result.trails
                else ()
            )
        diagnostic = getattr(result, "diagnostic", None)
        return _View("Trail enumeration", notes + ((diagnostic,) if diagnostic else ()), panels)
    if isinstance(result, ImpossibleSearchResult):
        notes = (
            f"complete: {result.complete}",
            f"termination: {result.termination}",
            f"attempted middle rounds: {result.attempted_rounds}",
            f"retained candidates: {len(result.candidates)}",
        )
        panels = tuple(
            panel
            for i, item in enumerate(result.candidates)
            for panel in _prefix(
                _view(item.trail).panels,
                f"Candidate {i}, middle round {item.middle_round}, {item.representation}",
            )
        )
        return _View("Impossible differential search", notes, panels)
    if isinstance(result, AutomaticWordImpossibleSATResult):
        return _View(
            "Impossible split search",
            (
                f"termination: {result.termination}",
                f"attempted middle rounds: {result.attempted_rounds}",
                f"selected middle round: {result.middle_round}",
            ),
            _view(result.trail).panels if result.trail is not None else (),
        )
    if isinstance(result, WordImpossibleSATTrail):
        return _view(result.boundary)
    if isinstance(result, ImpossiblePropagationBoundary):
        forward = tuple(float(bit.encoded) for bit in result.forward.bits)
        backward = tuple(float(bit.encoded) for bit in result.backward.bits)
        return _boundary_view(forward, backward, result.contradictory_positions, wordwise=False)
    if isinstance(result, WordwiseImpossibleSATTrail):
        middle = result.middle
        return _boundary_view(
            tuple(map(float, middle.forward_states)),
            tuple(map(float, middle.backward_states)),
            middle.contradictory_positions,
            wordwise=True,
        )
    if isinstance(result, TruncatedPropagationResult):
        return _View(
            "Deterministic truncated propagation",
            (f"primitive: {result.primitive}", "? means unknown, not a concrete difference."),
            _patterns(
                ((f"Round {i}", p) for i, p in enumerate(result.boundaries)), "Round boundary"
            ),
        )
    if isinstance(result, WordDeterministicTruncatedCharacteristic):
        patterns = (
            *result.input_patterns,
            *result.component_patterns,
            ("output", result.output_pattern),
        )
        return _View("Deterministic truncated characteristic", (), _patterns(patterns, "Pattern"))
    if isinstance(result, WordwiseDeterministicTruncatedCharacteristic):
        word_patterns = (
            *result.input_differences,
            *result.component_differences,
            ("output", result.output_differences),
        )
        return _View(
            "Wordwise truncated characteristic",
            ("Word activity categories; known words retain their exact values in the witness.",),
            _word_patterns(word_patterns, "Pattern"),
        )
    if isinstance(result, CPCharacteristicResult):
        view = _view(result.characteristic)
        return _View(
            view.title,
            (
                f"solver: {result.solver}",
                f"independently valid: {result.independently_valid}",
                *result.provenance,
                *view.notes,
            ),
            view.panels,
        )
    if isinstance(result, (ProbabilisticTruncatedTrail, SpeckSemiDeterministicTruncatedTrail)):
        return _View(
            "Truncated model characteristic",
            (
                "Legacy fixed-point model costs; not a measured whole-primitive probability.",
                f"weight: {result.weight:g}",
                f"input pattern: {result.input_pattern}",
                f"output pattern: {result.output_pattern}",
            ),
            (
                _weights(
                    (t.weight for t in result.transitions),
                    map(str, range(len(result.transitions))),
                    "Model transition costs",
                ),
            ),
        )
    if isinstance(result, XorDifferentialLinearSearchResult):
        panels = _view(result.trail).panels if result.trail is not None else ()
        return _View(
            "Differential-linear characteristic search",
            (
                f"partition: {result.partition}",
                f"component-product score: {result.score}",
                f"model optimization complete: {result.complete}",
                "Score is P_D * C_L²; deterministic middle has no probability estimate.",
            ),
            panels,
        )
    if isinstance(
        result,
        (
            WordDeterministicXorDifferentialLinearSATTrail,
            WordSemiDeterministicXorDifferentialLinearSATTrail,
        ),
    ):
        panels = (
            _bars(
                "Component objective contributions",
                ("differential", "2 × linear"),
                (result.differential.total_weight, 2 * result.linear.total_weight),
                "Objective weight (bits)",
            ),
        )
        if isinstance(result, WordSemiDeterministicXorDifferentialLinearSATTrail):
            panels += (
                _bars(
                    "Separate middle estimate",
                    ("middle",),
                    (result.middle_weight,),
                    "Middle model weight (bits)",
                ),
            )
        return _View(
            "Differential-linear characteristic",
            ("P_D * C_L² objective; middle support is not a probability estimate.",),
            panels,
        )
    if isinstance(result, SharedDifferencePairedSATTrail):
        return _View(
            "Paired differential characteristic",
            (),
            (
                _bars(
                    "Component weights",
                    ("left", "right"),
                    (result.left.total_weight, result.right.total_weight),
                    "Weight (bits)",
                ),
            ),
        )
    if isinstance(result, SharedDifferencePairedXorDifferentialLinearSATTrail):
        return _View(
            "Paired differential-linear characteristic",
            (),
            (
                _bars(
                    "Objective contributions",
                    ("paired differential", "2 × linear"),
                    (result.paired_differential.total_weight, 2 * result.linear.total_weight),
                    "Objective weight (bits)",
                ),
            ),
        )
    if isinstance(result, (MinimaxDifferentialResult, BoomerangSearchResult)):
        status = getattr(result.status, "value", result.status)
        witness = _view(result.trail) if result.trail is not None else _View("")
        return _View(
            "Restricted ARX boomerang search"
            if isinstance(result, BoomerangSearchResult)
            else "Minimax differential search",
            (
                f"status: {status}",
                f"proved minimum in model: {result.is_optimal}",
                *((result.diagnostic,) if result.diagnostic else ()),
                *witness.notes,
            ),
            witness.panels,
        )
    if isinstance(result, PartitionedDifferentialTrail):
        return _View(
            "Partitioned differential characteristic",
            (
                f"min-max objective: {result.objective_weight}",
                f"ordinary total weight: {result.total_weight}",
            ),
            (
                _bars(
                    "Key and data path weights",
                    ("key schedule", "data path"),
                    (result.key_schedule_weight, result.data_path_weight),
                    "Weight (bits)",
                ),
            ),
        )
    if isinstance(result, ARXBoomerangTrail):
        return _View(
            "Restricted ARX boomerang characteristic",
            (
                result.scope,
                f"model complete: {result.model_complete}",
                "Outer weight excludes switches; local switch probabilities are not a full probability.",
            ),
            (
                _bars(
                    "Outer characteristic weights",
                    ("upper", "lower"),
                    (_total_weight(result.upper), _total_weight(result.lower)),
                    "Weight (bits)",
                ),
                _bars(
                    "Local switch probabilities",
                    (name for name, _, _ in result.switches),
                    (p for _, _, p in result.switches),
                    "Local switch probability",
                ),
            ),
        )
    if isinstance(result, QuasidifferentialTrail):
        values = tuple(step.coefficient for _, step in result.steps)
        return _View(
            "Signed quasidifferential characteristic",
            (
                f"signed coefficient: {result.coefficient}",
                f"proved optimal: {result.is_optimal}",
                "Signed coefficients are not probabilities.",
            ),
            (
                _Panel(
                    "Signed local factors and their product",
                    tuple(name for name, _ in result.steps),
                    (
                        ("local coefficient", tuple(map(float, values))),
                        (
                            "cumulative coefficient",
                            tuple(map(float, accumulate(values, lambda a, b: a * b))),
                        ),
                    ),
                    "Signed coefficient",
                ),
            ),
        )
    if isinstance(result, FixedKeyProbabilityResult):
        values = tuple(trail.coefficient for trail in result.trails)
        panels = (
            (
                _Panel(
                    "Retained signed partial sums",
                    tuple(map(str, range(len(values)))),
                    (("signed partial sum", tuple(map(float, accumulate(values)))),),
                    "Signed sum",
                    "Retained trail index",
                ),
            )
            if values
            else ()
        )
        return _View(
            "Signed trail sum",
            (
                f"complete: {result.complete}",
                f"signed sum: {result.signed_sum}",
                f"event: {result.event}",
                f"key averaged: {result.key_averaged}",
                result.diagnostic or "",
                "A partial signed sum is not a probability proof.",
            ),
            panels,
        )
    if isinstance(result, ContinuousCorrelationResult):
        width = len(result.output_values)
        selected = tuple(
            float(bool(result.output_mask & (1 << (width - 1 - i)))) for i in range(width)
        )
        return _View(
            "Continuous differential heuristic",
            (
                f"model complete: {result.model_complete}",
                f"heuristic absolute product: {result.correlation:g}",
                "Heuristic correlations; not exact XOR probabilities.",
            ),
            (
                _Panel(
                    "Output correlations and selected mask bits",
                    tuple(map(str, range(width))),
                    (
                        ("signed output correlation", result.output_values),
                        ("selected mask bit", selected),
                    ),
                    "Heuristic correlation / mask bit",
                    "Output bit (MSB first)",
                ),
            ),
        )
    if isinstance(result, ActiveSBoxResult):
        activity_panels = (
            ()
            if result.model_objective is None
            else (
                _bars(
                    "Wordwise branch-number relaxation",
                    ("proved lower bound" if result.complete else "candidate objective",),
                    (result.model_objective,),
                    "Active S-box count",
                ),
            )
        )
        return _View(
            "Active-S-box relaxation",
            (
                f"status: {result.status}",
                f"complete: {result.complete}",
                "Relaxation bound; not an exact differential.",
            ),
            activity_panels,
        )
    from claasp.analysis.division_property import _DivisionPropertyTrail
    from claasp.representations.constraints.cp.trails import (
        ModularAddBoomerangTrailResult,
        PresentKeyScheduleXorDifferentialTrail,
        SBoxBoomerangTrailResult,
    )
    from claasp.representations.constraints.milp.trails import WordwiseActivityResult
    from claasp.semantics.cryptanalysis import (
        BoomerangTrail,
        Trail,
        TrailKind,
        XorDifferentialLinearTrail,
    )

    if isinstance(result, BoomerangTrail):
        return _View(
            "Boomerang characteristic",
            ("Model exponent 2p + r + 2q; not a measured full probability.",),
            (
                _bars(
                    "Model exponent contributions",
                    ("2 × upper", "switch", "2 × lower"),
                    (
                        2 * result.upper.total_weight,
                        result.switch.weight,
                        2 * result.lower.total_weight,
                    ),
                    "Model weight (bits)",
                ),
            ),
        )
    if isinstance(result, XorDifferentialLinearTrail):
        connector = log2(2 ** (result.connector.weight + 1) - 1)
        return _View(
            "Differential-linear connector model",
            ("Legacy objective p + log2(2^(r+1)-1) + 2q; connector term is model-specific.",),
            (
                _bars(
                    "Model objective contributions",
                    ("differential", "connector", "2 × linear"),
                    (result.differential.total_weight, connector, 2 * result.linear.total_weight),
                    "Model weight (bits)",
                ),
            ),
        )
    if isinstance(result, Trail):
        linear = result.kind is TrailKind.XOR_LINEAR
        return _View(
            "Component characteristic",
            (
                "Component-product evidence; not a whole-primitive hull.",
                f"input pattern: {result.input_pattern}",
                f"output pattern: {result.output_pattern}",
            ),
            (
                _weights(
                    (step.transition.weight for step in result.steps),
                    (step.component_id for step in result.steps),
                    "Absolute correlation weights" if linear else "Probability weights",
                ),
            ),
        )
    if isinstance(result, PresentKeyScheduleXorDifferentialTrail):
        return _View(
            "PRESENT key-schedule characteristic",
            (f"total weight: {result.total_weight}",),
            (
                _weights(
                    result.sbox_weights,
                    map(str, range(len(result.sbox_weights))),
                    "Key-schedule S-box weights",
                    xlabel="S-box transition",
                ),
            ),
        )
    if isinstance(result, (ModularAddBoomerangTrailResult, SBoxBoomerangTrailResult)):
        return _View(
            "Boomerang characteristic model",
            (
                f"outer search weight: {result.search_weight}",
                f"model exponent: {result.total_weight}",
                "Model exponent squares both outer trail probabilities; not a measured full probability.",
            ),
            (
                _bars(
                    "Model exponent contributions",
                    ("2 × upper", "switch", "2 × lower"),
                    (
                        2 * _total_weight(result.upper),
                        _model_weight(result.switch),
                        2 * _total_weight(result.lower),
                    ),
                    "Model weight (bits)",
                ),
            ),
        )
    if isinstance(result, WordwiseActivityResult):
        return _View(
            "Wordwise activity witness",
            (f"active S-boxes: {result.active_sboxes}", "Relaxation witness; no optimality claim."),
            (
                _bars(
                    "Retained activity assignment",
                    (n for n, _ in result.activity_assignment),
                    (v for _, v in result.activity_assignment),
                    "Activity indicator",
                ),
            ),
        )
    if isinstance(result, _DivisionPropertyTrail):
        if not result or isinstance(result[0], int):
            panels = (
                _Panel(
                    "SPN division-property bounds",
                    tuple(map(str, range(len(result)))),
                    (("active-bit bound", tuple(map(float, result))),),
                    "Division-property bound",
                    "Retained round step",
                ),
            )
        else:
            panels = tuple(
                _Panel(
                    f"Feistel round {i + 1}",
                    tuple(map(str, range(len(vectors)))),
                    (
                        ("left branch", tuple(float(a) for a, _ in vectors)),
                        ("right branch", tuple(float(b) for _, b in vectors)),
                    ),
                    "Division-vector active bits",
                    "Minimal vector index",
                )
                for i, vectors in enumerate(result)
            )
        return _View(
            "Division-property propagation",
            (
                "Retained recurrence bounds; Feistel antichains keep both branches for each minimal vector.",
            ),
            panels,
        )
    # S-box BCT entries are returned by the public CP characteristic search.
    from claasp.semantics.cryptanalysis import BoomerangConnectivity

    if isinstance(result, BoomerangConnectivity):
        return _View(
            "S-box boomerang connectivity",
            (
                f"count: {result.count}",
                f"input difference: {result.input_difference}",
                f"output difference: {result.output_difference}",
            ),
            (
                _bars(
                    "Exact local BCT probability",
                    ("S-box transition",),
                    (result.count / (1 << result.input_difference.width),),
                    "Local probability",
                ),
            ),
        )
    raise TypeError(f"No search evidence view for {type(result).__name__}")


def _prefix(panels, prefix):
    return tuple(
        _Panel(f"{prefix}: {p.title}", p.labels, p.series, p.ylabel, p.xlabel, p.states)
        for p in panels
    )


def _boundary_view(forward, backward, contradictions, *, wordwise):
    categories = ("zero", "known", "nonzero", "unknown") if wordwise else ("0", "1", "?")
    panel = _Panel(
        "Middle boundary",
        tuple(map(str, range(len(forward)))),
        (("forward", forward), ("backward", backward)),
        "Difference state",
        "Word position" if wordwise else "Bit position (MSB first)",
        categories,
    )
    conflict = _Panel(
        "Contradiction positions",
        panel.labels,
        (("contradiction", tuple(float(i in contradictions) for i in range(len(forward)))),),
        "Contradiction indicator",
        panel.xlabel,
    )
    return _View(
        "Impossible differential boundary",
        (
            f"contradictory positions: {contradictions}",
            "Abstract boundary contradiction; unknown states do not imply a fixed difference.",
        ),
        (panel, conflict),
    )


def _to_terminal(result, *, file=None):
    from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

    view = _view(result)
    print(view.title, file=file)
    for note in view.notes:
        if note:
            print(note, file=file)
    if not view.panels:
        print("No retained witness to display.", file=file)
    for panel in view.panels:
        print(panel.title, file=file)
        columns = (
            TableColumn("position", panel.xlabel),
            *(TableColumn(str(i), name) for i, (name, _) in enumerate(panel.series)),
        )
        rows = tuple(
            TableRow.of(
                label,
                *(
                    panel.states[int(values[i])] if panel.states else f"{values[i]:g}"
                    for _, values in panel.series
                ),
            )
            for i, label in enumerate(panel.labels)
        )
        print(render_terminal_table(Table(columns, rows)), file=file)


def _total_weight(characteristic: Any) -> float:
    """Read the common weight contract of backend-specific decoded evidence."""
    return characteristic.total_weight


def _model_weight(transition: Any) -> float:
    return transition.weight
