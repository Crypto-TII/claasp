"""Adapters from typed analysis results to immutable presentation sections.

Adapters only read their inputs. They never execute a primitive, solver,
statistical tool, or machine-learning framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import isinf

from claasp_next.analysis.avalanche import AvalancheResult
from claasp_next.analysis.component_properties import ComponentPropertyResult, PropertyClaim
from claasp_next.analysis.neural import NeuralExperimentResult
from claasp_next.analysis.neural_experiments import NeuralRun
from claasp_next.analysis.statistical_results import (
    DieharderReport, NISTFinalReport, StatisticalTestRun,
)
from claasp_next.annotations import ExecutionTrace
from claasp_next.catalogue.records import (
    AnalysisRecord, ComponentRecord, DriverRecord, PrimitiveRecord, RepresentationRecord,
)
from claasp_next.presentation.contracts import (
    Applicability, DiagnosticCode, EvidenceClass, PresentationDiagnostic, PresentationEvidence,
)
from claasp_next.presentation.formatting import FormatSpec, ValueKind
from claasp_next.presentation.model import (
    Alignment, ReportSection, Table, TableCell, TableColumn, TableRow,
)
from claasp_next.semantics.cryptanalysis import Trail, TrailSearchResult
from claasp_next.semantics.cryptanalysis.continuous import ContinuousHeuristicResult


@dataclass(frozen=True, slots=True)
class AdaptationResult:
    """A section or a typed reason why adaptation was unsupported."""

    section: ReportSection | None = None
    diagnostic: PresentationDiagnostic | None = None

    def __post_init__(self) -> None:
        if (self.section is None) == (self.diagnostic is None):
            raise ValueError("adaptation returns exactly one of section or diagnostic")


def _text(value: object, evidence: PresentationEvidence | None = None) -> TableCell:
    return TableCell(_canonical(value), FormatSpec(ValueKind.TEXT), evidence)


def _integer(value: int, evidence: PresentationEvidence | None = None) -> TableCell:
    return TableCell(value, FormatSpec(ValueKind.INTEGER), evidence)


def _number(value: float, kind: ValueKind, evidence: PresentationEvidence | None = None) -> TableCell:
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
        return "{" + ", ".join(
            f"{key}: {_canonical(item)}" for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        ) + "}"
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(_canonical(item) for item in value) + "]"
    if isinstance(value, (set, frozenset)):
        return "{" + ", ".join(sorted(_canonical(item) for item in value)) + "}"
    raise TypeError(f"unsupported presentation value {type(value).__name__}")


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
    """Present a trail summary and ordered transition evidence."""

    trail = result.trail if isinstance(result, TrailSearchResult) else result
    summary_rows = [
        TableRow((_text("kind"), _text(trail.kind.value))),
        TableRow((_text("input"), _text(f"0x{trail.input_pattern.value:x}/{trail.input_pattern.width}"))),
        TableRow((_text("output"), _text(f"0x{trail.output_pattern.value:x}/{trail.output_pattern.width}"))),
        TableRow((_text("total weight"), _number(trail.total_weight, ValueKind.WEIGHT))),
    ]
    if isinstance(result, TrailSearchResult):
        evidence = PresentationEvidence(
            EvidenceClass.EXACT if result.is_optimal else EvidenceClass.PROVED_BOUND,
            complete=result.is_optimal,
            bound_direction=None if result.is_optimal else "lower",
        )
        summary_rows.extend((
            TableRow((_text("lower bound"), _number(result.lower_bound, ValueKind.WEIGHT, evidence))),
            TableRow((_text("solver/method provenance"), _text(result.provenance))),
        ))
    summary = Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value", Alignment.RIGHT)),
        tuple(summary_rows), "Trail summary",
    )
    steps = Table(
        (
            TableColumn("step", "Step", Alignment.RIGHT),
            TableColumn("kind", "Kind"),
            TableColumn("input", "Input"),
            TableColumn("output", "Output"),
            TableColumn("ratio", "Exact ratio", Alignment.RIGHT),
            TableColumn("sign", "Sign", Alignment.RIGHT),
            TableColumn("weight", "Weight", Alignment.RIGHT),
            TableColumn("reference", "Graph location (evidence)"),
        ),
        tuple(
            TableRow((
                _integer(index), _text(step.transition.kind.value),
                _text(f"0x{step.transition.input_pattern.value:x}/{step.transition.input_pattern.width}"),
                _text(f"0x{step.transition.output_pattern.value:x}/{step.transition.output_pattern.width}"),
                _text(f"{step.transition.numerator}/{step.transition.denominator}"),
                _integer(step.transition.sign), _number(step.transition.weight, ValueKind.WEIGHT),
                _text(step.component_id),
            ))
            for index, step in enumerate(trail.steps, 1)
        ),
        "Ordered transition evidence",
        ("Graph locations are evidence references, not semantic report identity.",),
    )
    return ReportSection("Trail", tables=(summary, steps))


def trace_section(trace: ExecutionTrace) -> ReportSection:
    """Present an execution trace in its annotation order."""

    rows = tuple(
        TableRow((_integer(index), _text(entry.role.value), _text(_canonical(entry.value)), _text(entry.source_id)))
        for index, entry in enumerate(trace.annotation.entries)
    )
    table = Table(
        (
            TableColumn("order", "Order", Alignment.RIGHT), TableColumn("role", "Role"),
            TableColumn("value", "Value"), TableColumn("reference", "Graph location (evidence)"),
        ), rows, "Concrete trace",
        (f"Realization: {trace.annotation.realization_identity}",),
    )
    return ReportSection("Execution trace", tables=(table,))


def component_property_section(results: tuple[ComponentPropertyResult, ...] | list[ComponentPropertyResult]) -> ReportSection:
    """Present component properties in caller-supplied semantic order."""

    rows = []
    for result in results:
        evidence = _property_evidence(result)
        value = TableCell(evidence=evidence) if result.value is None else _text(result.value, evidence)
        rows.append(TableRow((
            _text(result.provenance.semantic_identity), _text(result.request.property.value),
            _text(result.request.domain.value), value, _text(evidence.classification.value),
            _text(evidence.applicability.value), _text(result.provenance.analysis_method),
            _text(result.provenance.graph_locations),
        )))
    table = Table(
        (
            TableColumn("component", "Semantic component"), TableColumn("property", "Property"),
            TableColumn("domain", "Domain"), TableColumn("value", "Value", Alignment.RIGHT),
            TableColumn("evidence", "Evidence"), TableColumn("applicability", "Applicability"),
            TableColumn("method", "Method"), TableColumn("references", "Graph locations (evidence)"),
        ), tuple(rows), "Component properties",
    )
    return ReportSection("Component properties", tables=(table,))


def avalanche_section(result: AvalancheResult) -> ReportSection:
    """Present empirical avalanche metadata, summaries, and the fixed matrix."""

    empirical = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=False)
    summary = Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value", Alignment.RIGHT)),
        (
            TableRow((_text("primitive"), _text(result.primitive_family))),
            TableRow((_text("input"), _text(result.input_name))),
            TableRow((_text("samples"), _integer(result.sample_count, empirical))),
            TableRow((_text("seed"), _integer(result.seed, empirical))),
            TableRow((_text("method"), _text(result.method, empirical))),
            TableRow((_text("maximum SAC bias"), _number(result.maximum_sac_bias, ValueKind.PROBABILITY, empirical))),
        ), "Avalanche summary",
    )
    matrix = Table(
        (TableColumn("input_bit", "Input bit", Alignment.RIGHT),) + tuple(
            TableColumn(f"output_{index}", f"Output {index}", Alignment.RIGHT)
            for index in range(result.output_bit_count)
        ),
        tuple(TableRow((_integer(index),) + tuple(
            _number(value, ValueKind.PROBABILITY, empirical) for value in row
        )) for index, row in enumerate(result.probabilities)),
        "Empirical output-flip probabilities",
    )
    return ReportSection("Avalanche", tables=(summary, matrix))


def _statistical_payload(result):
    return result.report if isinstance(result, StatisticalTestRun) else result


def dieharder_section(result: DieharderReport | StatisticalTestRun[DieharderReport]) -> ReportSection:
    """Present every Dieharder observation and preserve run provenance."""

    report = _statistical_payload(result)
    empirical = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=True)
    rows = tuple(TableRow((
        _integer(item.test_id), _text(item.test_name), _integer(item.ntuple),
        _integer(item.test_samples), _integer(item.pvalue_samples),
        _number(item.p_value, ValueKind.PROBABILITY, empirical), _text(item.assessment.value, empirical),
    )) for item in report.observations)
    notes = ()
    if isinstance(result, StatisticalTestRun):
        notes = (
            f"dataset sha256: {result.dataset_sha256}", f"suite: {result.suite} {result.suite_version}",
            "command: " + " ".join(result.command), f"runtime seconds: {result.runtime_seconds:.6g}",
        )
    table = Table((
        TableColumn("id", "ID", Alignment.RIGHT), TableColumn("test", "Test"),
        TableColumn("ntuple", "Ntuple", Alignment.RIGHT), TableColumn("samples", "Test samples", Alignment.RIGHT),
        TableColumn("p_samples", "P-value samples", Alignment.RIGHT), TableColumn("p_value", "P-value", Alignment.RIGHT),
        TableColumn("assessment", "Assessment"),
    ), rows, "Dieharder observations", notes)
    return ReportSection("Dieharder", tables=(table,))


def nist_section(result: NISTFinalReport | StatisticalTestRun[NISTFinalReport]) -> ReportSection:
    """Present every NIST STS row, including unavailable tests."""

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
        rows.append(TableRow((
            _integer(index), _text(item.test_name), _text(item.normalized_name),
            _text(item.bin_counts), p_value, _integer(item.passed_sequences, evidence),
            _integer(item.total_sequences, evidence), proportion, _text(evidence.classification.value),
        )))
    notes = ()
    if isinstance(result, StatisticalTestRun):
        notes = (
            f"dataset sha256: {result.dataset_sha256}", f"suite: {result.suite} {result.suite_version}",
            "command: " + " ".join(result.command), f"runtime seconds: {result.runtime_seconds:.6g}",
        )
    table = Table((
        TableColumn("row", "Row", Alignment.RIGHT), TableColumn("test", "Test"),
        TableColumn("normalized", "Normalized name"), TableColumn("bins", "Uniformity bins"),
        TableColumn("p_value", "P-value", Alignment.RIGHT), TableColumn("passed", "Passed", Alignment.RIGHT),
        TableColumn("total", "Total", Alignment.RIGHT), TableColumn("proportion", "Proportion", Alignment.RIGHT),
        TableColumn("evidence", "Evidence"),
    ), tuple(rows), "NIST STS summary", notes)
    return ReportSection("NIST STS", tables=(table,))


def neural_section(
    result: NeuralExperimentResult | None,
    run: NeuralRun,
    *,
    state: EvidenceClass = EvidenceClass.EMPIRICAL,
    diagnostic: PresentationDiagnostic | None = None,
) -> ReportSection:
    """Present a neural experiment without importing an ML framework."""

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
            TableRow((_text(f"validation accuracy epoch {index}"), _number(value, ValueKind.PROBABILITY, evidence)))
            for index, value in enumerate(result.validation_accuracy, 1)
        )
    elif diagnostic is not None:
        rows.append(TableRow((_text("diagnostic"), TableCell(diagnostic=diagnostic))))
    table = Table(
        (TableColumn("field", "Field"), TableColumn("value", "Value", Alignment.RIGHT)),
        tuple(rows), "Neural experiment",
        (f"options: {_canonical(provenance.options)}",),
    )
    return ReportSection("Neural experiment", tables=(table,))


def continuous_section(result: ContinuousHeuristicResult) -> ReportSection:
    """Present continuous-analysis values only as incomplete heuristic evidence."""

    evidence = PresentationEvidence(EvidenceClass.INCOMPLETE, complete=False, diagnostic=
        PresentationDiagnostic(DiagnosticCode.MISSING_EVIDENCE, "continuous model is heuristic, not a proof"))
    table = Table(
        (TableColumn("index", "Index", Alignment.RIGHT), TableColumn("correlation", "Correlation", Alignment.RIGHT)),
        tuple(TableRow((_integer(index), _number(value, ValueKind.CORRELATION)))
              for index, value in enumerate(result.values)),
        "Continuous heuristic values",
        (f"tolerance: {result.tolerance}", f"precision: {result.precision}",
         f"evidence: {evidence.classification.value}", f"provenance: {result.provenance}"),
    )
    return ReportSection("Continuous heuristic", tables=(table,))


def catalogue_section(records: tuple[object, ...] | list[object]) -> ReportSection:
    """Present a conservative capability summary from immutable catalogue records."""

    rows = []
    for record in records:
        if isinstance(record, PrimitiveRecord):
            kind, name, capability, restriction = "primitive", record.name, record.kind, record.authenticity
        elif isinstance(record, ComponentRecord):
            kind, name, capability, restriction = "component", record.name, record.primitive_wrapper, "—"
        elif isinstance(record, RepresentationRecord):
            kind, name, capability, restriction = "representation", record.name, record.kind, record.scope
        elif isinstance(record, AnalysisRecord):
            kind, name, capability, restriction = "analysis", record.name, record.evidence, record.restriction or "—"
        elif isinstance(record, DriverRecord):
            kind, name, capability, restriction = "driver", record.name, record.kind, record.availability
        else:
            raise TypeError(f"unsupported catalogue record {type(record).__name__}")
        rows.append(TableRow((_text(kind), _text(name), _text(capability), _text(restriction))))
    table = Table((
        TableColumn("record", "Record"), TableColumn("name", "Name"),
        TableColumn("capability", "Kind/capability"), TableColumn("restriction", "Restriction/authenticity"),
    ), tuple(rows), "Catalogue capabilities")
    return ReportSection("Catalogue", tables=(table,))


def adapt_result(result: object) -> AdaptationResult:
    """Adapt a supported typed result or return a typed unsupported diagnostic."""

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
    return AdaptationResult(diagnostic=PresentationDiagnostic(
        DiagnosticCode.UNSUPPORTED_RESULT,
        f"no presentation adapter for {type(result).__name__}",
        (("type", f"{type(result).__module__}.{type(result).__qualname__}"),),
    ))
