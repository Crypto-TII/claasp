"""Adapters from typed analysis results to immutable presentation sections.

Adapters only read their inputs. They never execute a primitive, solver,
statistical tool, or machine-learning framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from math import isinf

from claasp.analysis.avalanche import AvalancheResult
from claasp.analysis.component_properties import ComponentPropertyResult, PropertyClaim
from claasp.analysis.neural import NeuralExperimentResult
from claasp.analysis.neural_experiments import NeuralRun
from claasp.analysis.statistical_results import (
    DieharderReport,
    NISTFinalReport,
    StatisticalTestRun,
)
from claasp.annotations import ExecutionTrace
from claasp.catalogue.records import (
    AnalysisRecord,
    ComponentRecord,
    DriverRecord,
    PrimitiveRecord,
    RepresentationRecord,
)
from claasp.presentation.contracts import (
    Applicability,
    DiagnosticCode,
    EvidenceClass,
    PresentationDiagnostic,
    PresentationEvidence,
)
from claasp.presentation.formatting import FormatSpec, ValueKind
from claasp.presentation.model import (
    Alignment,
    ReportSection,
    Table,
    TableCell,
    TableColumn,
    TableRow,
)
from claasp.semantics.cryptanalysis import BitPattern, Trail, TrailSearchResult
from claasp.semantics.cryptanalysis.continuous import ContinuousHeuristicResult


@dataclass(frozen=True, slots=True)
class AdaptationResult:
    """A section or a typed reason why adaptation was unsupported.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (AdaptationResult.__dataclass_params__.frozen, tuple(field.name for field in fields(AdaptationResult)))
        (True, ('section', 'diagnostic'))
    """

    section: ReportSection | None = None
    diagnostic: PresentationDiagnostic | None = None

    def __post_init__(self) -> None:
        if (self.section is None) == (self.diagnostic is None):
            raise ValueError("adaptation returns exactly one of section or diagnostic")


def _text(value: object, evidence: PresentationEvidence | None = None) -> TableCell:
    return TableCell(_canonical(value), FormatSpec(ValueKind.TEXT), evidence)


def _integer(value: int, evidence: PresentationEvidence | None = None) -> TableCell:
    return TableCell(value, FormatSpec(ValueKind.INTEGER), evidence)


def _number(
    value: float, kind: ValueKind, evidence: PresentationEvidence | None = None
) -> TableCell:
    return TableCell(value, FormatSpec(kind), evidence)


def _canonical(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        if isinstance(value, float) and isinf(value):
            return "infinity" if value > 0 else "-infinity"
        return str(value)
    if isinstance(value, dict) or hasattr(value, "items"):
        return (
            "{"
            + ", ".join(
                f"{key}: {_canonical(item)}"
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            )
            + "}"
        )
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(_canonical(item) for item in value) + "]"
    if isinstance(value, (set, frozenset)):
        return "{" + ", ".join(sorted(_canonical(item) for item in value)) + "}"
    raise TypeError(f"unsupported presentation value {type(value).__name__}")


def _bit_pattern(pattern: BitPattern) -> str:
    width = pattern.width
    digits = (width + 3) // 4
    return f"0x{pattern.value:0{digits}x}"


def _ratio(numerator: int, denominator: int) -> str:
    reduced = Fraction(numerator, denominator)
    return f"{reduced.numerator}/{reduced.denominator}"


def _property_evidence(result: ComponentPropertyResult) -> PresentationEvidence:
    mapping = {
        PropertyClaim.EXACT: (EvidenceClass.EXACT, None),
        PropertyClaim.PROVED_LOWER_BOUND: (EvidenceClass.PROVED_BOUND, "lower"),
        PropertyClaim.PROVED_UPPER_BOUND: (EvidenceClass.PROVED_BOUND, "upper"),
        PropertyClaim.EMPIRICAL: (EvidenceClass.EMPIRICAL, None),
    }
    if result.claim is PropertyClaim.UNAVAILABLE:
        assert result.diagnostic is not None
        inapplicable = result.diagnostic.code.value == "inapplicable_domain"
        diagnostic = PresentationDiagnostic(
            DiagnosticCode.INAPPLICABLE if inapplicable else DiagnosticCode.MISSING_EVIDENCE,
            result.diagnostic.message,
            (("analysis_code", result.diagnostic.code.value),),
        )
        return PresentationEvidence(
            EvidenceClass.UNAVAILABLE,
            Applicability.INAPPLICABLE if inapplicable else Applicability.UNKNOWN,
            complete=result.complete,
            diagnostic=diagnostic,
        )
    classification, direction = mapping[result.claim]
    return PresentationEvidence(classification, complete=result.complete, bound_direction=direction)


def trail_section(result: Trail | TrailSearchResult) -> ReportSection:
    """Present a trail summary and ordered transition evidence.

    EXAMPLES::

        >>> try:
        ...     trail_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    trail = result.trail if isinstance(result, TrailSearchResult) else result
    summary_rows = [
        TableRow((_text("kind"), _text(trail.kind.value))),
        TableRow((_text("input"), _text(_bit_pattern(trail.input_pattern)))),
        TableRow((_text("output"), _text(_bit_pattern(trail.output_pattern)))),
        TableRow((_text("total weight"), _number(trail.total_weight, ValueKind.WEIGHT))),
    ]
    if isinstance(result, TrailSearchResult):
        evidence = PresentationEvidence(
            EvidenceClass.EXACT if result.is_optimal else EvidenceClass.PROVED_BOUND,
            complete=result.is_optimal,
            bound_direction=None if result.is_optimal else "lower",
        )
        summary_rows.extend(
            (
                TableRow(
                    (_text("lower bound"), _number(result.lower_bound, ValueKind.WEIGHT, evidence))
                ),
                TableRow(
                    (
                        _text("optimality"),
                        _text("proved optimal" if result.is_optimal else "not proved"),
                    )
                ),
                TableRow((_text("search method"), _text(result.metadata.technique))),
                TableRow((_text("solver"), _text(result.metadata.solver or "not used"))),
                TableRow(
                    (
                        _text("runtime"),
                        _text(
                            "not reported"
                            if result.metadata.runtime_seconds is None
                            else f"{result.metadata.runtime_seconds:.6f} seconds"
                        ),
                    )
                ),
                TableRow(
                    (
                        _text("peak memory"),
                        _text(
                            "not reported"
                            if result.metadata.peak_memory_bytes is None
                            else f"{result.metadata.peak_memory_bytes} bytes"
                        ),
                    )
                ),
            )
        )
        if result.metadata.solver_version is not None:
            summary_rows.insert(
                -2,
                TableRow((_text("solver version"), _text(result.metadata.solver_version))),
            )
    summary = Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value", Alignment.RIGHT)),
        tuple(summary_rows),
        "Trail summary",
    )
    if isinstance(result, TrailSearchResult) and result.component_transitions:
        transition_rows = tuple(
            TableRow(
                (
                    _integer(component.round_number),
                    _text(component.component),
                    _text(
                        "—"
                        if component.input_pattern is None
                        else _bit_pattern(component.input_pattern)
                    ),
                    _text(_bit_pattern(component.output_pattern)),
                    _text(
                        "1/1"
                        if component.local_transition is None
                        else _ratio(
                            component.local_transition.numerator,
                            component.local_transition.denominator,
                        )
                    ),
                    _integer(
                        1 if component.local_transition is None else component.local_transition.sign
                    ),
                    _number(component.weight, ValueKind.WEIGHT),
                    _text(component.component_id),
                )
            )
            for component in result.component_transitions
        )
    else:
        transition_rows = tuple(
            TableRow(
                (
                    _text("—"),
                    _text(step.transition.kind.value),
                    _text(_bit_pattern(step.transition.input_pattern)),
                    _text(_bit_pattern(step.transition.output_pattern)),
                    _text(_ratio(step.transition.numerator, step.transition.denominator)),
                    _integer(step.transition.sign),
                    _number(step.transition.weight, ValueKind.WEIGHT),
                    _text(step.component_id),
                )
            )
            for step in trail.steps
        )
    steps = Table(
        (
            TableColumn("round", "Round", Alignment.RIGHT),
            TableColumn("component", "Component"),
            TableColumn("input", "Input"),
            TableColumn("output", "Output"),
            TableColumn("ratio", "Exact ratio", Alignment.RIGHT),
            TableColumn("sign", "Sign", Alignment.RIGHT),
            TableColumn("weight", "Weight", Alignment.RIGHT),
            TableColumn("component_id", "Component ID"),
        ),
        transition_rows,
        "Component transitions",
    )
    return ReportSection("Trail", tables=(summary, steps))


def trace_section(trace: ExecutionTrace) -> ReportSection:
    """Present an execution trace in its annotation order.

    EXAMPLES::

        >>> try:
        ...     trace_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    rows = tuple(
        TableRow(
            (
                _integer(index),
                _text(entry.role.value),
                _text(_canonical(entry.value)),
                _text(entry.source_id),
            )
        )
        for index, entry in enumerate(trace.annotation.entries)
    )
    table = Table(
        (
            TableColumn("order", "Order", Alignment.RIGHT),
            TableColumn("role", "Role"),
            TableColumn("value", "Value"),
            TableColumn("component", "Component"),
        ),
        rows,
        "Concrete trace",
        (f"Realization: {trace.annotation.realization_identity}",),
    )
    return ReportSection("Execution trace", tables=(table,))


def component_property_section(
    results: tuple[ComponentPropertyResult, ...] | list[ComponentPropertyResult],
) -> ReportSection:
    """Present component properties in caller-supplied semantic order.

    EXAMPLES::

        >>> try:
        ...     component_property_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    rows = []
    for result in results:
        evidence = _property_evidence(result)
        value = (
            TableCell(evidence=evidence) if result.value is None else _text(result.value, evidence)
        )
        rows.append(
            TableRow(
                (
                    _text(result.provenance.semantic_identity),
                    _text(result.request.property.value),
                    _text(result.request.domain.value),
                    value,
                    _text(evidence.classification.value),
                    _text(evidence.applicability.value),
                    _text(result.provenance.analysis_method),
                    _text(result.provenance.graph_locations),
                )
            )
        )
    table = Table(
        (
            TableColumn("component", "Semantic component"),
            TableColumn("property", "Property"),
            TableColumn("domain", "Domain"),
            TableColumn("value", "Value", Alignment.RIGHT),
            TableColumn("evidence", "Evidence"),
            TableColumn("applicability", "Applicability"),
            TableColumn("method", "Method"),
            TableColumn("references", "Graph locations (evidence)"),
        ),
        tuple(rows),
        "Component properties",
    )
    return ReportSection("Component properties", tables=(table,))


def avalanche_section(result: AvalancheResult) -> ReportSection:
    """Present empirical avalanche metadata, summaries, and the fixed matrix.

    EXAMPLES::

        >>> try:
        ...     avalanche_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    empirical = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=False)
    summary = Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value", Alignment.RIGHT)),
        (
            TableRow((_text("primitive"), _text(result.primitive_family))),
            TableRow((_text("input"), _text(result.input_name))),
            TableRow((_text("samples"), _integer(result.sample_count, empirical))),
            TableRow((_text("seed"), _integer(result.seed, empirical))),
            TableRow((_text("method"), _text(result.method, empirical))),
            TableRow(
                (
                    _text("maximum SAC bias"),
                    _number(result.maximum_sac_bias, ValueKind.PROBABILITY, empirical),
                )
            ),
        ),
        "Avalanche summary",
    )
    matrix = Table(
        (TableColumn("input_bit", "Input bit", Alignment.RIGHT),)
        + tuple(
            TableColumn(f"output_{index}", f"Output {index}", Alignment.RIGHT)
            for index in range(result.output_bit_count)
        ),
        tuple(
            TableRow(
                (_integer(index),)
                + tuple(_number(value, ValueKind.PROBABILITY, empirical) for value in row)
            )
            for index, row in enumerate(result.probabilities)
        ),
        "Empirical output-flip probabilities",
    )
    return ReportSection("Avalanche", tables=(summary, matrix))


def _statistical_payload(result):
    return result.report if isinstance(result, StatisticalTestRun) else result


def dieharder_section(
    result: DieharderReport | StatisticalTestRun[DieharderReport],
) -> ReportSection:
    """Present every Dieharder observation and preserve run provenance.

    EXAMPLES::

        >>> try:
        ...     dieharder_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    report = _statistical_payload(result)
    empirical = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=True)
    rows = tuple(
        TableRow(
            (
                _integer(item.test_id),
                _text(item.test_name),
                _integer(item.ntuple),
                _integer(item.test_samples),
                _integer(item.pvalue_samples),
                _number(item.p_value, ValueKind.PROBABILITY, empirical),
                _text(item.assessment.value, empirical),
            )
        )
        for item in report.observations
    )
    notes = ()
    if isinstance(result, StatisticalTestRun):
        notes = (
            f"dataset sha256: {result.dataset_sha256}",
            f"suite: {result.suite} {result.suite_version}",
            "command: " + " ".join(result.command),
            f"runtime seconds: {result.runtime_seconds:.6g}",
        )
    table = Table(
        (
            TableColumn("id", "ID", Alignment.RIGHT),
            TableColumn("test", "Test"),
            TableColumn("ntuple", "Ntuple", Alignment.RIGHT),
            TableColumn("samples", "Test samples", Alignment.RIGHT),
            TableColumn("p_samples", "P-value samples", Alignment.RIGHT),
            TableColumn("p_value", "P-value", Alignment.RIGHT),
            TableColumn("assessment", "Assessment"),
        ),
        rows,
        "Dieharder observations",
        notes,
    )
    return ReportSection("Dieharder", tables=(table,))


def nist_section(result: NISTFinalReport | StatisticalTestRun[NISTFinalReport]) -> ReportSection:
    """Present every NIST STS row, including unavailable tests.

    EXAMPLES::

        >>> try:
        ...     nist_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    report = _statistical_payload(result)
    rows = []
    for index, item in enumerate(report.rows, 1):
        if item.uniformity_p_value is None or item.total_sequences == 0:
            diagnostic = PresentationDiagnostic(
                DiagnosticCode.MISSING_EVIDENCE, "NIST STS did not report this value"
            )
            p_value = TableCell(diagnostic=diagnostic)
            proportion = TableCell(diagnostic=diagnostic)
            evidence = PresentationEvidence(EvidenceClass.UNAVAILABLE, diagnostic=diagnostic)
        else:
            evidence = PresentationEvidence(EvidenceClass.EMPIRICAL)
            p_value = _number(item.uniformity_p_value, ValueKind.PROBABILITY, evidence)
            proportion = _number(item.proportion, ValueKind.PROBABILITY, evidence)
        rows.append(
            TableRow(
                (
                    _integer(index),
                    _text(item.test_name),
                    _text(item.normalized_name),
                    _text(item.bin_counts),
                    p_value,
                    _integer(item.passed_sequences, evidence),
                    _integer(item.total_sequences, evidence),
                    proportion,
                    _text(evidence.classification.value),
                )
            )
        )
    notes = ()
    if isinstance(result, StatisticalTestRun):
        notes = (
            f"dataset sha256: {result.dataset_sha256}",
            f"suite: {result.suite} {result.suite_version}",
            "command: " + " ".join(result.command),
            f"runtime seconds: {result.runtime_seconds:.6g}",
        )
    table = Table(
        (
            TableColumn("row", "Row", Alignment.RIGHT),
            TableColumn("test", "Test"),
            TableColumn("normalized", "Normalized name"),
            TableColumn("bins", "Uniformity bins"),
            TableColumn("p_value", "P-value", Alignment.RIGHT),
            TableColumn("passed", "Passed", Alignment.RIGHT),
            TableColumn("total", "Total", Alignment.RIGHT),
            TableColumn("proportion", "Proportion", Alignment.RIGHT),
            TableColumn("evidence", "Evidence"),
        ),
        tuple(rows),
        "NIST STS summary",
        notes,
    )
    return ReportSection("NIST STS", tables=(table,))


def neural_section(
    result: NeuralExperimentResult | None,
    run: NeuralRun,
    *,
    state: EvidenceClass = EvidenceClass.EMPIRICAL,
    diagnostic: PresentationDiagnostic | None = None,
) -> ReportSection:
    """Present a neural experiment without importing an ML framework.

    EXAMPLES::

        >>> try:
        ...     neural_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if state in {EvidenceClass.INCOMPLETE, EvidenceClass.FAILED, EvidenceClass.SKIPPED}:
        evidence = PresentationEvidence(state, complete=False, diagnostic=diagnostic)
    elif result is None:
        raise ValueError("a successful neural summary requires a result")
    else:
        evidence = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=True)
    provenance = run.provenance
    rows = [
        TableRow((_text("architecture"), _text(run.experiment.architecture))),
        TableRow((_text("dataset digest"), _text(provenance.dataset_digest))),
        TableRow((_text("dataset seed"), _integer(provenance.dataset_seed))),
        TableRow((_text("partition seed"), _integer(provenance.partition_seed))),
        TableRow((_text("driver"), _text(provenance.driver))),
        TableRow((_text("driver version"), _text(provenance.driver_version))),
        TableRow((_text("state"), _text(evidence.classification.value))),
    ]
    if result is not None:
        rows.extend(
            TableRow(
                (
                    _text(f"validation accuracy epoch {index}"),
                    _number(value, ValueKind.PROBABILITY, evidence),
                )
            )
            for index, value in enumerate(result.validation_accuracy, 1)
        )
    elif diagnostic is not None:
        rows.append(TableRow((_text("diagnostic"), TableCell(diagnostic=diagnostic))))
    table = Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value", Alignment.RIGHT)),
        tuple(rows),
        "Neural experiment",
        (f"options: {_canonical(provenance.options)}",),
    )
    return ReportSection("Neural experiment", tables=(table,))


def continuous_section(result: ContinuousHeuristicResult) -> ReportSection:
    """Present continuous-analysis values only as incomplete heuristic evidence.

    EXAMPLES::

        >>> try:
        ...     continuous_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    evidence = PresentationEvidence(
        EvidenceClass.INCOMPLETE,
        complete=False,
        diagnostic=PresentationDiagnostic(
            DiagnosticCode.MISSING_EVIDENCE, "continuous model is heuristic, not a proof"
        ),
    )
    table = Table(
        (
            TableColumn("index", "Index", Alignment.RIGHT),
            TableColumn("correlation", "Correlation", Alignment.RIGHT),
        ),
        tuple(
            TableRow((_integer(index), _number(value, ValueKind.CORRELATION)))
            for index, value in enumerate(result.values)
        ),
        "Continuous heuristic values",
        (
            f"tolerance: {result.tolerance}",
            f"precision: {result.precision}",
            f"evidence: {evidence.classification.value}",
            f"provenance: {result.provenance}",
        ),
    )
    return ReportSection("Continuous heuristic", tables=(table,))


def catalogue_section(records: tuple[object, ...] | list[object]) -> ReportSection:
    """Present a conservative capability summary from immutable catalogue records.

    EXAMPLES::

        >>> try:
        ...     catalogue_section()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    rows = []
    for record in records:
        if isinstance(record, PrimitiveRecord):
            kind, name, capability, restriction = (
                "primitive",
                record.name,
                record.kind,
                record.authenticity,
            )
        elif isinstance(record, ComponentRecord):
            kind, name, capability, restriction = (
                "component",
                record.name,
                record.primitive_wrapper,
                "—",
            )
        elif isinstance(record, RepresentationRecord):
            kind, name, capability, restriction = (
                "representation",
                record.name,
                record.kind,
                record.scope,
            )
        elif isinstance(record, AnalysisRecord):
            kind, name, capability, restriction = (
                "analysis",
                record.name,
                record.evidence,
                record.restriction or "—",
            )
        elif isinstance(record, DriverRecord):
            kind, name, capability, restriction = (
                "driver",
                record.name,
                record.kind,
                record.availability,
            )
        else:
            raise TypeError(f"unsupported catalogue record {type(record).__name__}")
        rows.append(TableRow((_text(kind), _text(name), _text(capability), _text(restriction))))
    table = Table(
        (
            TableColumn("record", "Record"),
            TableColumn("name", "Name"),
            TableColumn("capability", "Kind/capability"),
            TableColumn("restriction", "Restriction/authenticity"),
        ),
        tuple(rows),
        "Catalogue capabilities",
    )
    return ReportSection("Catalogue", tables=(table,))


def adapt_result(result: object) -> AdaptationResult:
    """Adapt a supported typed result or return a typed unsupported diagnostic.

    EXAMPLES::

        >>> try:
        ...     adapt_result()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    dispatch = (
        ((Trail, TrailSearchResult), trail_section),
        ((ExecutionTrace,), trace_section),
        ((AvalancheResult,), avalanche_section),
        ((DieharderReport,), dieharder_section),
        ((NISTFinalReport,), nist_section),
        ((ContinuousHeuristicResult,), continuous_section),
    )
    for types, adapter in dispatch:
        if isinstance(result, types):
            return AdaptationResult(section=adapter(result))
    return AdaptationResult(
        diagnostic=PresentationDiagnostic(
            DiagnosticCode.UNSUPPORTED_RESULT,
            f"no presentation adapter for {type(result).__name__}",
            (("type", f"{type(result).__module__}.{type(result).__qualname__}"),),
        )
    )
