Presenting and exporting results
================================

CLAASP presents already-produced typed results. ``present(result)`` never runs
an analysis, solver, statistical program, or neural-training framework. The
returned ``ReportData`` is immutable and keeps evidence, applicability,
citations, realization identity, and execution metadata separate.

Trail and trace summaries
-------------------------

A trail report shows its kind, input and output patterns, total weight, proof
bound, optimality, search method, solver, runtime, memory measurement when
available, and the primitive component responsible for each transition:

.. doctest::

   >>> from claasp.primitives import Speck
   >>> result = Speck(number_of_rounds=2).analysis.find_lowest_weight_xor_differential_trail()
   >>> result.show()  # doctest: +ELLIPSIS
   Trail
   ...

``show()`` is the convenient interactive form. The explicit presentation API
below provides immutable report data and selectable output formats for tools
and exports.

The default searches use a zero key difference. Their reports include every
cipher-state component but omit the resulting all-zero key schedule. A
related-key result must retain its key-schedule propagation as well.

.. doctest::

   >>> from claasp.presentation import render_section, trail_section
   >>> from claasp.semantics.cryptanalysis import (
   ...     Trail, TrailKind, TrailSearchMetadata, TrailSearchResult, TrailStep,
   ...     Transition, XorDifference,
   ... )
   >>> transition = Transition(
   ...     TrailKind.XOR_DIFFERENTIAL,
   ...     XorDifference(1, 4), XorDifference(3, 4), 4, 16,
   ... )
   >>> trail = Trail(
   ...     TrailKind.XOR_DIFFERENTIAL,
   ...     XorDifference(1, 4), XorDifference(3, 4),
   ...     (TrailStep("sbox_0_0", transition),),
   ... )
   >>> metadata = TrailSearchMetadata("fixed PRESENT evidence")
   >>> section = trail_section(TrailSearchResult(trail, 2.0, metadata))
   >>> "total weight" in render_section(section, format="terminal")
   True
   >>> section.tables[1].rows[0].cells[-1].text
   'sbox_0_0'

``trace_section(execution_trace)`` similarly lists intermediate values in
execution order and names the component that produced each value.

Exact, bounded, and unavailable properties
------------------------------------------

Property tables do not turn a bound or an unavailable value into an exact
score. The value column uses ``≤`` or ``≥`` for proved bounds, and unavailable
rows retain a typed diagnostic and applicability:

.. doctest::

   >>> from claasp.analysis import (
   ...     ComponentProperty, ComponentPropertyResult, PropertyClaim,
   ...     PropertyDomain, PropertyRequest,
   ... )
   >>> from claasp.analysis.component_properties import (
   ...     ComponentAnalysisProvenance, DiagnosticCode, PropertyDiagnostic,
   ... )
   >>> from claasp.presentation import component_property_section
   >>> provenance = ComponentAnalysisProvenance("AES MixColumns", "fixed field evidence")
   >>> request = PropertyRequest(
   ...     ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR)
   >>> exact = ComponentPropertyResult(request, PropertyClaim.EXACT, 5, True, provenance)
   >>> bounded = ComponentPropertyResult(
   ...     request, PropertyClaim.PROVED_UPPER_BOUND, 5, False, provenance)
   >>> unavailable = ComponentPropertyResult(
   ...     PropertyRequest(ComponentProperty.BOOMERANG_UNIFORMITY, PropertyDomain.WORD_LINEAR),
   ...     PropertyClaim.UNAVAILABLE, None, False, provenance,
   ...     PropertyDiagnostic(DiagnosticCode.INAPPLICABLE_DOMAIN, "not a lookup table"),
   ... )
   >>> rows = component_property_section((exact, bounded, unavailable)).tables[0].rows
   >>> [row.cells[3].text for row in rows]
   ['5', '≤5', 'inapplicable: not a lookup table']
   >>> [row.cells[4].text for row in rows]
   ['exact', 'proved_bound', 'unavailable']

Avalanche and statistical summaries
-----------------------------------

Avalanche matrices always remain empirical and retain sample count and seed.
NIST STS and Dieharder adapters preserve every parser row, including weak,
failed, and unavailable observations. A ``StatisticalTestRun`` also contributes
dataset SHA-256, suite/tool version, command, and runtime.

.. doctest::

   >>> from claasp.analysis.avalanche import AvalancheResult
   >>> from claasp.presentation import avalanche_section
   >>> avalanche = AvalancheResult(
   ...     "speck", "plaintext", 4, 9, ((0.0, 0.5), (1.0, 0.25)))
   >>> summary, matrix = avalanche_section(avalanche).tables
   >>> (summary.rows[2].cells[1].text, summary.rows[3].cells[1].text)
   ('4', '9')
   >>> matrix.rows[1].cells[2].text
   '0.25'

Text and report-data export
---------------------------

Terminal, Markdown, and CSV consume the same immutable table. ``report_data``
returns ordinary JSON-compatible dictionaries and lists. It is a presentation
export, not the versioned graph/result serialization format.

.. doctest::

   >>> from claasp.presentation import (
   ...     MathematicalProvenance, PresentationProvenance, ReportData,
   ...     ReportSection, Table, TableColumn, TableRow, render_csv_table,
   ...     render_markdown_table, report_data,
   ... )
   >>> table = Table((TableColumn("property", "Property"), TableColumn("value", "Value")),
   ...               (TableRow.of("branch number", "5"),))
   >>> render_markdown_table(table).splitlines()[-1]
   '| branch number | 5 |'
   >>> render_csv_table(table)
   'Property,Value\nbranch number,5\n'
   >>> report = ReportData(
   ...     "Component report", (ReportSection("Properties", tables=(table,)),),
   ...     PresentationProvenance(MathematicalProvenance("fixed evidence")),
   ... )
   >>> report_data(report)["provenance"]["mathematical"]["method"]
   'fixed evidence'

``write_report`` is separate from adaptation and rendering. It requires an
explicit format and matching extension, writes UTF-8 with deterministic
newlines, does not create parents unless requested, and refuses to overwrite
unless ``overwrite=True``. It never derives directories from primitive or test
names and never adds an implicit timestamp.

Optional plotting
-----------------

Plotting is requested explicitly and imports Matplotlib only inside the driver
method. Set a noninteractive backend before importing ``pyplot`` in headless
programs::

   import matplotlib
   matplotlib.use("Agg")
   from claasp.drivers.renderers import MatplotlibPresentationDriver

   artifact = MatplotlibPresentationDriver().avalanche_matrix(avalanche)
   artifact.figure.savefig("avalanche.png")

Radar charts additionally require one ``RadarScale`` per included property.
Each scale states its mathematical domain, finite range, and whether higher or
lower is better. Axis labels show that contract and the evidence class.
Unavailable, inapplicable, unscaled, or nonnumeric properties are omitted and
listed in ``artifact.omitted``; unrelated domains are never normalized by an
implicit common formula.
