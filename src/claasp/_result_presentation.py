"""Storage-free convenience methods for retained search-result presentation.

These internal mixins hold no result data and import no presentation libraries
at module load time. Type-specific adapters continue to interpret the evidence.
The API authority uses ``__public_api_methods__`` to track their inherited
methods on public receivers without exporting the internal mixin classes.
"""


class PlotMixin:
    """Share plot delegation without adding storage to slotted result classes."""

    __slots__ = ()
    __public_api_methods__ = ("plot",)

    def plot(self, *, details=False, value_format="hex", show=True, save_to=None):
        """Plot retained evidence without repeating a search.

        Requires the optional ``presentation`` extra. ``show=False`` suppresses
        display; ``save_to`` writes a file. Impossible-differential results
        show the retained round path, both meeting states and contradictions;
        ``details=True`` includes component states and ``value_format`` selects
        notation for exact word annotations. Returns a ``FigureArtifact`` with
        the figure and numeric series. Result-specific views and examples are
        documented on the result class.

        EXAMPLES::

            >>> from claasp.analysis.composed_search import ImpossibleSearchResult
            >>> result = ImpossibleSearchResult((), (1,), False, 'solver unknown')
            >>> artifact = result.plot(show=False)
            >>> artifact.kind, artifact.series
            ('search_evidence', ())
            >>> import matplotlib.pyplot as plt
            >>> plt.close(artifact.figure)
        """
        from claasp.drivers.renderers._search_results import _plot

        return _plot(self, details=details, value_format=value_format, show=show, save_to=save_to)


class TerminalMixin:
    """Share terminal delegation while allowing specialized result overrides."""

    __slots__ = ()
    __public_api_methods__ = ("to_terminal",)

    def to_terminal(self, *, details=False, value_format="hex", file=None):
        """Print retained evidence and status without repeating a search.

        For exact trails, ``details=True`` includes component values and
        ``value_format`` selects ``hex``, ``binary`` (``0b`` prefix), or
        ``underscore_one`` (zero as ``_``), or ``dot_one`` (zero as ``.``),
        with one as ``1``, MSB first.
        Output goes to standard output unless ``file`` is supplied. No plotting
        dependency is required. See the result class for its evidence-specific
        interpretation and examples.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.analysis.composed_search import ImpossibleSearchResult
            >>> stream = StringIO()
            >>> result = ImpossibleSearchResult((), (1,), False, 'solver unknown')
            >>> result.to_terminal(file=stream)
            >>> 'solver unknown' in stream.getvalue()
            True
        """
        from claasp.presentation._search_results import _to_terminal

        _to_terminal(self, details=details, value_format=value_format, file=file)


class ImpossibleTerminalMixin(TerminalMixin):
    """Share a binary terminal default across impossible-differential evidence."""

    __slots__ = ()
    __public_api_methods__ = ("to_terminal",)

    def to_terminal(self, *, details=False, value_format="binary", include_key=False, file=None):
        """Print impossible evidence as MSB-first binary patterns by default.

        Both exact and partial patterns preserve their bit widths. ``?`` and
        abstract nonzero words ``*`` retain their meanings. ``details=True``
        includes component states in the same notation. Explicit ``hex`` and
        ``underscore_one`` and ``dot_one`` formats remain available. One
        contradiction-marker row lies between the two meeting differences.
        Named key inputs are hidden unless ``include_key=True``; this also
        applies to nonzero key differences. Retained evidence is unchanged.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.semantics.cryptanalysis import (
            ...     ImpossiblePropagationBoundary, TruncatedXorDifference)
            >>> boundary = ImpossiblePropagationBoundary(
            ...     TruncatedXorDifference.parse('0010'),
            ...     TruncatedXorDifference.parse('00?1'))
            >>> output = StringIO()
            >>> boundary.to_terminal(file=output)
            >>> '0b0010' in output.getvalue(), '0b00?1' in output.getvalue()
            (True, True)
            >>> '0x' in output.getvalue()
            False
            >>> output = StringIO()
            >>> boundary.to_terminal(value_format='hex', file=output)
            >>> '0b0010' in output.getvalue()  # Partial meeting pairs stay aligned in binary.
            True
            >>> output = StringIO()
            >>> boundary.to_terminal(value_format='dot_one', file=output)
            >>> '..1.' in output.getvalue(), '..?1' in output.getvalue()
            (True, True)
        """
        from claasp.presentation._impossible import _to_terminal

        return _to_terminal(
            self, details=details, value_format=value_format, include_key=include_key, file=file
        )


class ImpossiblePlotMixin(PlotMixin):
    """Specialize impossible-trail plots without exposing key options elsewhere."""

    __slots__ = ()
    __public_api_methods__ = ("plot",)

    def plot(
        self, *, details=False, value_format="hex", include_key=False, show=True, save_to=None
    ):
        """Plot retained impossible evidence, hiding named key inputs by default.

        ``include_key=True`` shows key input differences, including zeros.
        ``details=True`` adds retained component states. ``value_format`` selects
        exact word annotations; ``dot_one`` uses dots for zeros and ``1`` for ones.
        Requires the optional ``presentation`` extra.
        No search is repeated and retained differences are never modified.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis import (
            ...     ImpossiblePropagationBoundary, TruncatedXorDifference)
            >>> boundary = ImpossiblePropagationBoundary(
            ...     TruncatedXorDifference.parse('01'), TruncatedXorDifference.parse('00'))
            >>> artifact = boundary.plot(include_key=True, show=False)
            >>> artifact.kind
            'search_evidence'
            >>> import matplotlib.pyplot as plt
            >>> plt.close(artifact.figure)
        """
        from claasp.drivers.renderers._impossible import _plot

        return _plot(
            self,
            details=details,
            value_format=value_format,
            include_key=include_key,
            show=show,
            save_to=save_to,
        )
