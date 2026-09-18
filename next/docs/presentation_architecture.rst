Presentation architecture
=========================

Contracts and boundaries
------------------------

``claasp_next.presentation`` replaces the legacy mutable ``Report`` dispatcher
with frozen contracts. ``TableColumn``, ``TableCell``, ``TableRow``, ``Table``,
``ReportSection``, and ``ReportData`` contain ordered presentation data. Result
adapters consume typed trails, traces, M10.11 component results, M10.12
avalanche/statistical results, M10.13 neural experiments, continuous
heuristics, and catalogue records. They never invoke the producing analysis.

``PresentationEvidence`` distinguishes ``exact``, ``proved_bound``,
``empirical``, ``unavailable``, ``skipped``, ``incomplete``, and ``failed``.
Applicability is independent. Exact evidence must be complete; inapplicable
evidence must be unavailable; non-success states require a typed diagnostic.
This prevents a missing p-value, bounded branch number, heuristic correlation,
or failed training run from appearing successful.

Provenance and citations
------------------------

``PresentationProvenance`` has separate ``mathematical``, ``primitive``, and
``execution`` fields. Mathematical provenance carries methods, sources, and
fixed-evidence references. Primitive provenance identifies the mathematical
primitive and selected realization. Execution provenance identifies a driver,
version, command, sorted options, and runtime. ``ReproducibilityMetadata``
keeps dataset identities, named seeds, and sorted environment facts. Citations
are immutable identifiers/titles/locators and occur in human-readable and
JSON-compatible report data.

Ordering and formatting
-----------------------

Adapters preserve order already defined by typed semantics: trail steps,
annotations, property requests, parser rows, matrix bits, metric epochs, and
catalogue records. They never sort by generated descriptions or rely on
mutable dictionary insertion. Component ids may appear only in columns
explicitly labelled as graph-location evidence.

``FormatSpec`` defines deterministic text for decimal and hexadecimal integers,
bit and word vectors, probabilities, correlations, weights, booleans, bounds,
unavailable values, and diagnostics. Formatting uses no locale or unstable
object representation. Markdown escapes pipes and expands newlines with
``<br>``; terminal output expands multiline cells before alignment; CSV uses
the standard-library ``csv`` writer with ``\n`` endings.

Export is not serialization
---------------------------

``report_data`` returns recursively JSON-compatible report data, and
``write_report`` may encode it as JSON for report interchange. These functions
do not define a versioned graph or result schema and do not promise round-trip
reconstruction. M10.15 owns versioned serialization, diagram compilation, code
generation, native helpers, and evaluator artifacts.

File output is distinct from adaptation and rendering. Callers provide the
complete path, explicit format, matching extension, parent-creation policy,
and overwrite policy. The writer rejects ``..`` traversal, symbolic-link
targets, directories, mismatched extensions, implicit parents, and accidental
overwrite.

Optional integrations
---------------------

The core imports only the standard library and existing typed CLAASP contracts.
The dataframe adapter imports pandas only when ``to_dataframe`` is called.
``MatplotlibPresentationDriver`` imports Matplotlib only when a plot method is
called. Presentation imports neither solver packages nor ML frameworks.

Radar normalization is an explicit ``RadarScale`` keyed by property and
``PropertyDomain`` with minimum, maximum, direction, and label. Out-of-range
values are errors. Unavailable, inapplicable, nonnumeric, or unscaled values
are omitted and recorded. Bounds retain a ``proved_bound`` label. Figure
artifacts carry deterministic series, labels, omitted cases, and renderer
identity so headless tests inspect structure rather than pixels.

Diagnostics and extension points
--------------------------------

``adapt_result`` returns either a section or a stable typed diagnostic such as
``unsupported_result``. A new adapter reads a typed result, maps evidence
without promotion, preserves source order and provenance, and adds fixed
dependency-free tests. Add an optional renderer only after the table/report
data view is complete.

.. doctest::

   >>> from claasp_next.analysis.avalanche import AvalancheResult
   >>> from claasp_next.presentation import present, render_report
   >>> result = AvalancheResult("demo", "input", 2, 7, ((0.0, 1.0),))
   >>> "empirical_paired_evaluation" in render_report(present(result))
   True
